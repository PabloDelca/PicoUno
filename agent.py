"""PicoUno de GCA: agente local con OpenRouter y herramientas seguras."""
from __future__ import annotations

import asyncio
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus, urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

try:
    from openrouter import OpenRouter
except ImportError as exc:
    raise SystemExit("Falta OpenRouter. Ejecuta .venv\\Scripts\\pip.exe install -r requirements.txt") from exc

try:
    import httpx as _httpx
except ImportError:
    _httpx = None  # web_search deshabilitado si httpx no está instalado


APP_ROOT = Path(__file__).resolve().parent
ROOT = APP_ROOT
load_dotenv(APP_ROOT / ".env")
API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
MODEL = os.getenv("OPENROUTER_MODEL", "").strip() or "openai/gpt-4o-mini"
WORKSPACE_ID = os.getenv("OPENROUTER_WORKSPACE_ID", "").strip() or None
DEFAULT_HOST = "127.0.0.1"
HOST = os.getenv("GCA_HOST", "").strip() or DEFAULT_HOST
PORT = int(os.getenv("GCA_PORT", "").strip() or "8000")
MAX_AGENT_STEPS = max(1, int(os.getenv("GCA_MAX_STEPS", "20")))
MAX_TOTAL_AGENT_STEPS = max(MAX_AGENT_STEPS, int(os.getenv("GCA_MAX_TOTAL_STEPS", str(MAX_AGENT_STEPS * 10))))
MAX_REPEATED_TOOL_CALLS = max(2, int(os.getenv("GCA_MAX_REPEATED_TOOL_CALLS", "3")))
MAX_RESPONSE_SEGMENTS = min(3, max(1, int(os.getenv("GCA_MAX_RESPONSE_SEGMENTS", "3"))))
COMMAND_TIMEOUT = int(os.getenv("GCA_COMMAND_TIMEOUT", "120"))
MODEL_CACHE_TTL = int(os.getenv("GCA_MODEL_CACHE_TTL", "3600"))
RATE_LIMIT_REQUESTS = int(os.getenv("GCA_RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW = int(os.getenv("GCA_RATE_LIMIT_WINDOW", "60"))
HISTORY_MAX_MESSAGES = int(os.getenv("GCA_HISTORY_MAX_MESSAGES", "40"))
HISTORY_MAX_CHARS = int(os.getenv("GCA_HISTORY_MAX_CHARS", "120000"))
API_RATE_LIMIT_REQUESTS = int(os.getenv("GCA_API_RATE_LIMIT_REQUESTS", "120"))
API_RATE_LIMIT_WINDOW = int(os.getenv("GCA_API_RATE_LIMIT_WINDOW", "60"))
ACCESS_TOKEN = os.getenv("GCA_ACCESS_TOKEN", "").strip()
COMMAND_MODE = os.getenv("GCA_COMMAND_MODE", "disabled").strip().casefold()
if COMMAND_MODE not in {"disabled", "full"}:
    COMMAND_MODE = "disabled"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_RETAINED_RUNS = 100
PROTECTED_NAMES = {".env", ".git", ".venv", ".gca"}
EXCLUDED_NAMES = {".env", ".git", ".venv", ".gca", "__pycache__", "node_modules"}
SECRET_PATTERN = re.compile(r'''(?i)((?:openrouter[_-]?api[_-]?key|api[_-]?key|token|secret|password)\s*[=:]\s*)(["']?)([^"'\s,;]+)(\2)''')
SECRET_NAME_PATTERN = re.compile(r"(?i)(?:api[_-]?key|token|secret|password)")
MODEL_CACHE_PATH = APP_ROOT / ".gca" / "models.json"
CONVERSATION_PATH = APP_ROOT / ".gca" / "conversation.json"
WORKSPACE_ROOT = ROOT
SELECTED_FILES: list[str] = []
WORKSPACE_CONTEXT = ""
MAX_WORKSPACE_ENTRIES = 250
MAX_TOOL_LIST_ENTRIES = 500
MAX_CONTEXT_BYTES = 180_000
MAX_AGENT_MESSAGE_CHARS = max(32_000, int(os.getenv("GCA_MAX_AGENT_MESSAGE_CHARS", "180000")))
MAX_AGENT_TOOL_CHARS = max(4_000, int(os.getenv("GCA_MAX_AGENT_TOOL_CHARS", "16000")))

SYSTEM_PROMPT = """Eres GCA Pico. Responde en español, breve y claro.
Trabaja solo dentro de la carpeta de trabajo indicada. Inspecciona antes de modificar.
Usa herramientas para afirmar hechos sobre archivos o comandos. No expongas secretos.
Prioriza acciones directas; no repitas búsquedas equivalentes sin resultados. `search_files` admite texto literal y expresiones regulares.
Explica brevemente cada acción y finaliza con el resultado y archivos afectados."""
CHAT_ONLY_SYSTEM_PROMPT = """Eres GCA Pico en modo SOLO CHAT. Responde en español, breve y claro.
No tienes acceso a carpetas, archivos, herramientas ni comandos. No afirmes que ejecutaste acciones externas.
Explica conceptos y responde la pregunta directamente."""

@asynccontextmanager
async def _lifespan(_: FastAPI):
    if not _is_loopback_host(HOST) and not ACCESS_TOKEN:
        raise RuntimeError("GCA_ACCESS_TOKEN es obligatorio cuando GCA_HOST no es loopback.")
    _load_model_cache()
    _load_conversation()
    yield


app = FastAPI(title="PicoUno", version="0.5.1", lifespan=_lifespan)
history: list[dict[str, str]] = []
CHAT_ONLY = False
client: OpenRouter | None = OpenRouter(api_key=API_KEY, x_open_router_title="PicoUno") if API_KEY else None
model_catalog: list[dict[str, Any]] = []
model_catalog_fetched_at = 0.0
model_catalog_source = "none"
chat_request_times: dict[str, deque[float]] = {}
api_request_times: dict[str, deque[float]] = {}
rate_limit_lock = threading.Lock()
model_catalog_lock = threading.RLock()
SESSION_TOKEN = hashlib.sha256(("picouno-session:" + ACCESS_TOKEN).encode()).hexdigest() if ACCESS_TOKEN else ""
# Nota: si ACCESS_TOKEN está vacío, SESSION_TOKEN es "" y la auth se desactiva.
# Esto es intencional: solo se exige auth cuando HOST no es loopback (ver _lifespan).


@app.middleware("http")
async def _protect_api(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        response = await call_next(request)
        if request.url.path == "/":
            response.headers["Cache-Control"] = "no-store"
        return response
    client_id = request.client.host if request.client else "unknown"
    retry_after = _consume_api_rate_limit(client_id)
    if retry_after is not None:
        return JSONResponse({"detail": "Demasiadas solicitudes."}, status_code=429, headers={"Retry-After": str(retry_after)})
    _prune_runs()
    if ACCESS_TOKEN and request.url.path != "/api/auth":
        authorization = request.headers.get("authorization", "")
        bearer = authorization[7:].strip() if authorization.casefold().startswith("bearer ") else ""
        cookie = request.cookies.get("gca_session", "")
        bearer_ok = bool(bearer) and secrets.compare_digest(bearer, ACCESS_TOKEN)
        cookie_ok = bool(cookie) and secrets.compare_digest(cookie, SESSION_TOKEN)
        if not bearer_ok and not cookie_ok:
            return JSONResponse({"detail": "Autenticación requerida."}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    return await call_next(request)


def _credential_fingerprint() -> str:
    return hashlib.sha256(API_KEY.encode()).hexdigest()[:16] if API_KEY else ""


def _model_item(model: Any) -> dict[str, Any]:
    raw = model.model_dump() if hasattr(model, "model_dump") else model if isinstance(model, dict) else {
        key: getattr(model, key, None) for key in ("id", "name", "canonical_slug", "context_length", "pricing")
    }
    return {key: raw.get(key) for key in ("id", "name", "canonical_slug", "context_length", "pricing") if raw.get(key) is not None}


def _load_model_cache() -> None:
    global model_catalog, model_catalog_fetched_at, model_catalog_source
    with model_catalog_lock:
        try:
            payload = json.loads(MODEL_CACHE_PATH.read_text(encoding="utf-8"))
            cached = payload.get("models", [])
            fetched = float(payload.get("fetched_at", 0))
            if payload.get("credential_fingerprint") == _credential_fingerprint() and payload.get("workspace_id") == WORKSPACE_ID and isinstance(cached, list) and cached and fetched:
                model_catalog, model_catalog_fetched_at, model_catalog_source = cached, fetched, "disk"
        except (OSError, ValueError, TypeError):
            return


def _fetch_model_catalog(force: bool = False) -> tuple[list[dict[str, Any]], bool]:
    global model_catalog, model_catalog_fetched_at, model_catalog_source
    with model_catalog_lock:
        now = time.time()
        if model_catalog and not force and now - model_catalog_fetched_at < MODEL_CACHE_TTL:
            return list(model_catalog), True
        if client is None:
            raise RuntimeError("Configura OPENROUTER_API_KEY para recuperar modelos.")
        response = client.models.list_for_user(security={"bearer": API_KEY}, limit=500)
        items = getattr(response, "data", None) or getattr(response, "result", None) or []
        if hasattr(items, "model_dump"):
            items = items.model_dump()
        if isinstance(items, dict):
            items = items.get("data", [])
        catalog = [_model_item(item) for item in items]
        if not catalog:
            raise RuntimeError("OpenRouter no devolvió modelos disponibles.")
        model_catalog, model_catalog_fetched_at, model_catalog_source = catalog, now, "openrouter"
        try:
            MODEL_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            MODEL_CACHE_PATH.write_text(json.dumps({"fetched_at": now, "credential_fingerprint": _credential_fingerprint(), "workspace_id": WORKSPACE_ID, "models": catalog}, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass
        return list(catalog), False


def _consume_rate_limit(bucket: dict[str, deque[float]], client_id: str, request_limit: int, window: int, monotonic_now: float | None = None) -> int | None:
    if request_limit <= 0 or window <= 0:
        return None
    current = time.monotonic() if monotonic_now is None else monotonic_now
    cutoff = current - window
    with rate_limit_lock:
        timestamps = bucket.setdefault(client_id or "unknown", deque())
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= request_limit:
            return max(1, int(window - (current - timestamps[0]) + .999))
        timestamps.append(current)
        return None


def _consume_chat_rate_limit(client_id: str, monotonic_now: float | None = None) -> int | None:
    return _consume_rate_limit(chat_request_times, client_id, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW, monotonic_now=monotonic_now)


def _consume_api_rate_limit(client_id: str, monotonic_now: float | None = None) -> int | None:
    return _consume_rate_limit(api_request_times, client_id, API_RATE_LIMIT_REQUESTS, API_RATE_LIMIT_WINDOW, monotonic_now=monotonic_now)


def _resolve_model_alias(catalog: list[dict[str, Any]], requested: str) -> str:
    value = requested.strip()
    for item in catalog:
        if value in {item.get("id"), item.get("canonical_slug")}:
            return value
    matches = [item for item in catalog if str(item.get("name") or "").strip().casefold() == value.casefold()]
    if len(matches) > 1:
        raise ValueError("El nombre del modelo es ambiguo; usa su ID.")
    if len(matches) == 1:
        resolved = matches[0].get("id") or matches[0].get("canonical_slug")
        if resolved:
            return str(resolved)
    raise ValueError("Modelo no disponible para el workspace.")


def _trim_history() -> None:
    paired: list[dict[str, str]] = []
    pending_user: dict[str, str] | None = None
    for item in history:
        if item.get("role") == "user":
            pending_user = item
        elif item.get("role") == "assistant" and pending_user is not None:
            paired.extend((pending_user, item))
            pending_user = None
    history[:] = paired
    max_messages = max(2, HISTORY_MAX_MESSAGES)
    max_messages -= max_messages % 2
    max_chars = max(2, HISTORY_MAX_CHARS)
    per_message = max(1, max_chars // 2)
    marker = "[…historial truncado…]"
    for item in history:
        content = item.get("content", "")
        if len(content) > per_message:
            compact_marker = marker if per_message >= len(marker) else "[…]" if per_message >= 3 else "…"
            item["content"] = content[:max(0, per_message - len(compact_marker))] + compact_marker
    while len(history) > max_messages:
        if len(history) >= 2:
            del history[:2]
        else:
            del history[0]
    while len(history) > 2 and sum(len(item.get("content", "")) for item in history) > max_chars:
        if len(history) >= 2:
            del history[:2]
        else:
            break


def _port_is_available(host: str, port: int) -> bool:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for family, socktype, proto, _, address in addresses:
        try:
            with socket.socket(family, socktype, proto) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(address)
                probe.listen(1)
            return True
        except OSError:
            continue
    return False


def _bind_server_socket(host: str, port: int) -> socket.socket:
    """Reserva el socket que Uvicorn usará, evitando una comprobación TOCTOU."""
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OSError(f"No se pudo resolver {host}:{port}: {exc}") from exc
    last_error: OSError | None = None
    for family, socktype, proto, _, address in addresses:
        server_socket = socket.socket(family, socktype, proto)
        try:
            server_socket.bind(address)
            server_socket.listen(socket.SOMAXCONN)
            server_socket.setblocking(False)
            return server_socket
        except OSError as exc:
            last_error = exc
            server_socket.close()
    raise OSError(f"No se puede enlazar {host}:{port}: {last_error}") from last_error


def _is_loopback_host(host: str) -> bool:
    value = host.strip().strip("[]").casefold()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20_000)
    model: str | None = Field(default=None, max_length=200)


class ConversationRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=2_000)
    files: list[str] = Field(default_factory=list, max_length=200)


class DeleteConversationRequest(BaseModel):
    confirmed: bool = False


class AuthRequest(BaseModel):
    token: str = Field(min_length=1, max_length=500)


TOOLS = [
    {"type": "function", "function": {"name": "list_files", "description": "Lista archivos.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}, "limit": {"type": "integer"}}, "additionalProperties": False}}},
    {"type": "function", "function": {"name": "read_file", "description": "Lee texto.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, "required": ["path"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "write_file", "description": "Crea o reemplaza texto.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "edit_file", "description": "Sustituye texto exacto.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"}, "new_text": {"type": "string"}, "replace_all": {"type": "boolean"}}, "required": ["path", "old_text", "new_text"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "move_file", "description": "Mueve un archivo.", "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}}, "required": ["source", "destination"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "archive_file", "description": "Archiva recuperablemente.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "search_files", "description": "Busca nombres y contenido; query puede ser texto literal o expresión regular.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "path": {"type": "string"}, "limit": {"type": "integer"}, "regex": {"type": "boolean"}}, "required": ["query"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "run_command", "description": "Ejecuta PowerShell en primer plano.", "parameters": {"type": "object", "properties": {"command": {"type": "string"}, "timeout": {"type": "integer"}}, "required": ["command"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "web_search", "description": "Busca Internet y devuelve URLs.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "max_results": {"type": "integer"}}, "required": ["query"], "additionalProperties": False}}},
]
if COMMAND_MODE != "full":
    TOOLS = [tool for tool in TOOLS if tool["function"]["name"] != "run_command"]


@dataclass
class Run:
    run_id: str
    message: str
    model: str
    chat_only: bool = False
    stop: threading.Event = field(default_factory=threading.Event)
    events: asyncio.Queue[dict[str, Any]] = field(default_factory=asyncio.Queue)
    thread_events: queue.Queue[tuple[str, Any]] = field(default_factory=queue.Queue)
    thread_events_lock: threading.Lock = field(default_factory=threading.Lock)
    process: subprocess.Popen[str] | None = None
    process_lock: threading.Lock = field(default_factory=threading.Lock)
    stream: Any = None
    stream_lock: threading.Lock = field(default_factory=threading.Lock)
    done: bool = False
    finished: asyncio.Event = field(default_factory=asyncio.Event)


runs: dict[str, Run] = {}
active_run: Run | None = None
runs_lock = threading.RLock()
run_lock = asyncio.Lock()
state_lock = asyncio.Lock()


def _safe_path(raw_path: str, *, allow_root: bool = True) -> Path:
    candidate = (WORKSPACE_ROOT / ((raw_path or ".").strip())).resolve()
    if candidate != WORKSPACE_ROOT and WORKSPACE_ROOT not in candidate.parents:
        raise ValueError("La ruta debe permanecer dentro de la carpeta de trabajo.")
    if not allow_root and candidate == WORKSPACE_ROOT:
        raise ValueError("La raíz no es un archivo válido.")
    relative = candidate.relative_to(WORKSPACE_ROOT)
    if any(part.casefold() in PROTECTED_NAMES for part in relative.parts):
        raise ValueError("La ruta está protegida (.env, .git, .venv o .gca).")
    return candidate


def _relative(path: Path) -> str:
    return path.relative_to(WORKSPACE_ROOT).as_posix() or "."


def _workspace_path(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser().resolve()
    if not candidate.is_dir():
        raise ValueError("La carpeta de trabajo no existe o no es un directorio.")
    return candidate


def _excluded(path: Path, root: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        return True
    return any(part.casefold() in EXCLUDED_NAMES or part.casefold().startswith(".env.") or part.casefold().endswith((".pyc", ".pyo")) for part in parts)


def _workspace_listing(root: Path, limit: int = MAX_WORKSPACE_ENTRIES) -> dict[str, Any]:
    entry_limit = min(max(int(limit), 1), MAX_WORKSPACE_ENTRIES)
    tree: list[str] = []
    files: list[str] = []
    truncated = False
    for current, dirs, names in os.walk(root):
        current_path = Path(current)
        dirs[:] = sorted(name for name in dirs if not _excluded(current_path / name, root))
        depth = len(current_path.relative_to(root).parts)
        if depth >= 4:
            dirs[:] = []
        for name in sorted(dirs + names):
            item = current_path / name
            if _excluded(item, root):
                continue
            relative = item.relative_to(root).as_posix()
            tree.append(relative + ("/" if item.is_dir() else ""))
            if len(tree) > entry_limit:
                tree.pop()
                truncated = True
                break
            if item.is_file() and len(files) < entry_limit:
                files.append(relative)
        if truncated:
            break
    return {"tree": tree, "files": files, "truncated": truncated}


def _build_workspace_context(root: Path, selected: list[str]) -> str:
    listing = _workspace_listing(root)
    blocks: list[str] = []
    used = 0
    for raw in selected:
        candidate = (root / raw).resolve()
        if candidate == root or root not in candidate.parents or _excluded(candidate, root) or not candidate.is_file():
            raise ValueError(f"El archivo seleccionado no es válido: {raw}")
        if candidate.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"El archivo seleccionado supera 2 MB: {raw}")
        relative = candidate.relative_to(root).as_posix()
        block = "\n\n--- " + relative + " ---\n" + candidate.read_text(encoding="utf-8", errors="replace")
        used += len(block.encode())
        if used > MAX_CONTEXT_BYTES:
            raise ValueError("La selección supera el límite de contexto inicial.")
        blocks.append(block)
    tree = "\n".join(listing["tree"]) or "(carpeta vacía)"
    return f"Carpeta de trabajo activa: {root}\nÁrbol filtrado:\n{tree}\nArchivos seleccionados:{''.join(blocks) or ' (ninguno)'}"


def _save_conversation() -> bool:
    try:
        if not WORKSPACE_CONTEXT and not CHAT_ONLY:
            CONVERSATION_PATH.unlink(missing_ok=True)
            return True
        payload = {
            "version": 1,
            "mode": "chat" if CHAT_ONLY else "workspace",
            "workspace": str(WORKSPACE_ROOT),
            "selected_files": SELECTED_FILES,
            "history": history,
        }
        CONVERSATION_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = CONVERSATION_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(CONVERSATION_PATH)
        return True
    except OSError as exc:
        print("[WARN] No se pudo persistir la conversación: " + _redact(str(exc)), flush=True)
        return False


def _load_conversation() -> bool:
    global WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history
    try:
        payload = json.loads(CONVERSATION_PATH.read_text(encoding="utf-8"))
        selected_raw = payload.get("selected_files", [])
        messages_raw = payload.get("history", [])
        if not isinstance(selected_raw, list) or not isinstance(messages_raw, list):
            raise ValueError("Estado de conversación inválido.")
        selected = [str(item).strip() for item in selected_raw if str(item).strip()]
        messages = [
            {"role": item["role"], "content": item["content"]}
            for item in messages_raw
            if isinstance(item, dict)
            and item.get("role") in {"user", "assistant"}
            and isinstance(item.get("content"), str)
        ]
        if payload.get("mode", "workspace") == "chat":
            WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history = ROOT, [], "", True, messages
            _trim_history()
            return True
        root = _workspace_path(str(payload.get("workspace", "")))
        context = _build_workspace_context(root, selected)
        WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history = root, selected, context, False, messages
        _trim_history()
        return True
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _list_files(path: str = ".", recursive: bool = False, limit: int = 200) -> dict[str, Any]:
    directory = _safe_path(path)
    if not directory.is_dir():
        raise ValueError("El directorio no existe.")
    entry_limit = min(max(int(limit), 1), MAX_TOOL_LIST_ENTRIES)
    entries = []
    truncated = False
    iterator = directory.rglob("*") if recursive else directory.iterdir()
    for item in iterator:
        try:
            _safe_path(_relative(item))
        except ValueError:
            continue
        if len(entries) >= entry_limit:
            truncated = True
            break
        entries.append(_relative(item) + ("/" if item.is_dir() else ""))
    return {"path": _relative(directory), "entries": sorted(entries), "truncated": truncated}


def _read_file(path: str, start_line: int | None = None, end_line: int | None = None) -> dict[str, Any]:
    file_path = _safe_path(path, allow_root=False)
    if not file_path.is_file():
        raise ValueError("El archivo no existe.")
    if file_path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("El archivo supera 2 MB.")
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    first = int(start_line) if start_line is not None else 1
    last = int(end_line) if end_line is not None else len(lines)
    if first < 1:
        raise ValueError("start_line debe ser mayor que 0.")
    if last < 1:
        raise ValueError("end_line debe ser mayor que 0.")
    if last < first:
        raise ValueError("end_line debe ser mayor o igual que start_line.")
    return {"path": _relative(file_path), "start_line": first, "end_line": min(last, len(lines)), "content": "".join(lines[first - 1:last])}


def _write_file(path: str, content: str) -> dict[str, Any]:
    if len(content.encode()) > MAX_FILE_BYTES:
        raise ValueError("El contenido supera 2 MB.")
    file_path = _safe_path(path, allow_root=False)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    has_bom = file_path.is_file() and file_path.read_bytes().startswith(b"\xef\xbb\xbf")
    file_path.write_text(content, encoding="utf-8-sig" if has_bom else "utf-8")
    return {"path": _relative(file_path), "bytes": file_path.stat().st_size, "written": True}


def _edit_file(path: str, old_text: str, new_text: str, replace_all: bool = False) -> dict[str, Any]:
    file_path = _safe_path(path, allow_root=False)
    if not file_path.is_file():
        raise ValueError("El archivo no existe.")
    raw = file_path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("El archivo supera 2 MB.")
    if b"\x00" in raw:
        raise ValueError("No se pueden editar archivos binarios.")
    encoding = "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ValueError("El archivo no usa una codificación UTF-8 válida.") from exc
    count = text.count(old_text)
    if count == 0:
        raise ValueError("old_text no se encontró.")
    if count > 1 and not replace_all:
        raise ValueError(f"old_text aparece {count} veces; confirma replace_all=true.")
    updated = text.replace(old_text, new_text, -1 if replace_all else 1)
    if len(updated.encode(encoding)) > MAX_FILE_BYTES:
        raise ValueError("El contenido resultante supera 2 MB.")
    file_path.write_bytes(updated.encode(encoding))
    return {"path": _relative(file_path), "replacements": count if replace_all else 1, "written": True}


def _move_file(source: str, destination: str) -> dict[str, Any]:
    src, dst = _safe_path(source, allow_root=False), _safe_path(destination, allow_root=False)
    if not src.exists():
        raise ValueError("El origen no existe.")
    if dst.exists():
        raise ValueError("El destino ya existe.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return {"source": _relative(src), "destination": _relative(dst), "moved": True}


def _archive_file(path: str) -> dict[str, Any]:
    src = _safe_path(path, allow_root=False)
    if not src.is_file():
        raise ValueError("Solo se pueden archivar archivos.")
    relative = src.relative_to(WORKSPACE_ROOT)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = WORKSPACE_ROOT / ".gca" / "archive" / stamp / relative
    index = 1
    while dst.exists():
        dst = WORKSPACE_ROOT / ".gca" / "archive" / f"{stamp}-{index}" / relative
        index += 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return {"source": relative.as_posix(), "archive": dst.relative_to(WORKSPACE_ROOT).as_posix(), "archived": True}


def _redact(text: str) -> str:
    redacted = SECRET_PATTERN.sub(r"\1\2***\2", str(text))
    values = {value for name, value in os.environ.items() if value and SECRET_NAME_PATTERN.search(name)}
    if API_KEY:
        values.add(API_KEY)
    for value in sorted(values, key=len, reverse=True):
        redacted = redacted.replace(value, "***")
    return redacted


def _subprocess_env() -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if not SECRET_NAME_PATTERN.search(name)}


class _SearchParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self.current: dict[str, str] | None = None
        self.current_tag = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        classes = (data.get("class") or "").split()
        if tag == "a" and "result__a" in classes:
            self.current = {"title": "", "url": data.get("href") or ""}
            self.current_tag = "a"
        elif "result__snippet" in classes and self.results:
            self.current = self.results[-1]
            self.current_tag = tag

    def handle_data(self, data: str) -> None:
        if self.current is None:
            return
        if self.current_tag == "a":
            self.current["title"] += data
        else:
            self.current["snippet"] = self.current.get("snippet", "") + data

    def handle_endtag(self, tag: str) -> None:
        if self.current is not None and tag == self.current_tag:
            if self.current not in self.results and "title" in self.current:
                self.results.append(self.current)
            self.current, self.current_tag = None, ""


def _web_search(query: str, max_results: int = 5) -> dict[str, Any]:
    if _httpx is None:
        raise RuntimeError("httpx no está instalado. Ejecuta: pip install httpx")
    query = query.strip()
    if not query:
        raise ValueError("query no puede estar vacío.")
    response = _httpx.get("https://html.duckduckgo.com/html/?q=" + quote_plus(query), headers={"User-Agent": "PicoUno/0.4"}, timeout=20)
    response.raise_for_status()
    parser = _SearchParser()
    parser.feed(response.text)
    results, seen = [], set()
    for item in parser.results:
        raw = item.get("url", "")
        parsed = urlparse(raw)
        url = parse_qs(parsed.query).get("uddg", [raw])[0]
        if not url or url in seen:
            continue
        seen.add(url)
        results.append({"title": " ".join(item.get("title", "").split()), "snippet": " ".join(item.get("snippet", "").split()), "url": url})
        if len(results) >= min(max(int(max_results), 1), 10):
            break
    return {"query": query, "results": results, "count": len(results)}


def _set_process(run: Run, process: subprocess.Popen[str] | None) -> None:
    with run.process_lock:
        run.process = process


def _kill_process(run: Run) -> bool:
    with run.process_lock:
        process = run.process
        if process is None or process.poll() is not None:
            return False
        try:
            process.kill()
            return True
        except OSError:
            return False


def _request_stop(run: Run) -> None:
    run.stop.set()
    _close_model_stream(run)
    _kill_process(run)


async def _run_command_stream(run: Run, arguments: str) -> dict[str, Any]:
    if COMMAND_MODE != "full":
        return {"ok": False, "error": "run_command está deshabilitado. Configura GCA_COMMAND_MODE=full para habilitarlo."}
    try:
        parsed = json.loads(arguments or "{}")
        command = str(parsed.get("command", "")).strip()
        timeout = min(max(int(parsed.get("timeout", COMMAND_TIMEOUT)), 1), 600)
    except Exception as exc:
        return {"ok": False, "error": "Argumentos inválidos: " + str(exc)}
    if not command:
        return {"ok": False, "error": "command no puede estar vacío."}
    try:
        process = subprocess.Popen(["powershell.exe", "-NoLogo", "-NoProfile", "-Command", command], cwd=WORKSPACE_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1, env=_subprocess_env())
    except Exception as exc:
        return {"ok": False, "error": _redact(str(exc))}
    _set_process(run, process)
    output: list[str] = []
    started = time.perf_counter()
    output_queue: queue.Queue[str | None] = queue.Queue()
    def read_output() -> None:
        assert process.stdout is not None
        for line in iter(process.stdout.readline, ""):
            output_queue.put(line.rstrip("\r\n"))
        process.stdout.close()
        output_queue.put(None)
    threading.Thread(target=read_output, daemon=True).start()
    timed_out = False
    try:
        while True:
            if run.stop.is_set():
                _kill_process(run)
                break
            elif time.perf_counter() - started >= timeout:
                timed_out = True
                _kill_process(run)
                break
            try:
                line = output_queue.get_nowait()
            except queue.Empty:
                if process.poll() is not None and output_queue.empty():
                    break
                await asyncio.sleep(0.02)
                continue
            if line is not None:
                safe = _redact(line)
                output.append(safe)
                await _emit(run, "command_output", {"line": safe})
            elif process.poll() is not None:
                break
        code = process.wait(timeout=2)
    except Exception:
        _kill_process(run)
        code = process.poll()
        if code is None:
            code = -1
    finally:
        with run.process_lock:
            if run.process is process:
                run.process = None
    elapsed = round(time.perf_counter() - started, 3)
    cancelled = run.stop.is_set()
    result = {"command": _redact(command), "output": "\n".join(output), "return_code": code, "cancelled": cancelled, "timed_out": timed_out, "elapsed": elapsed}
    return {"ok": code == 0 and not cancelled and not timed_out, "result": json.dumps(result, ensure_ascii=False)}


def _search_files(query: str, path: str = ".", limit: int = 200, regex: bool = False) -> dict[str, Any]:
    raw_query = query.strip()
    needle = raw_query.casefold()
    if not needle:
        raise ValueError("query no puede estar vacío.")
    base = _safe_path(path)
    if not base.is_dir():
        raise ValueError("El directorio no existe.")
    match_limit = min(max(int(limit), 1), MAX_TOOL_LIST_ENTRIES)
    auto_regex = bool(re.search(r"\.\*|\.\+|\\[AbBdDsSwWZ]|\[[^]]+\]|\(\?", raw_query))
    pattern = None
    if regex or auto_regex:
        try:
            pattern = re.compile(raw_query, re.IGNORECASE)
        except re.error as exc:
            if regex:
                raise ValueError(f"Expresión regular inválida: {exc}") from exc
    def matches(text: str) -> bool:
        return bool(pattern.search(text)) if pattern is not None else needle in text.casefold()

    results: list[dict[str, Any]] = []
    total_scanned_bytes = 0
    max_scanned_bytes = 10 * 1024 * 1024
    for item in base.rglob("*"):
        if _excluded(item, WORKSPACE_ROOT):
            continue
        relative = _relative(item)
        candidate: dict[str, Any] | None = None
        if matches(relative):
            candidate = {"path": relative, "kind": "directory" if item.is_dir() else "file"}
        elif item.is_file() and item.stat().st_size <= MAX_FILE_BYTES:
            if total_scanned_bytes >= max_scanned_bytes:
                return {"query": query, "regex": pattern is not None, "matches": results, "truncated": True}
            try:
                text = item.read_text(encoding="utf-8", errors="ignore")
                total_scanned_bytes += len(text.encode("utf-8", errors="ignore"))
                for number, line in enumerate(text.splitlines(), 1):
                    if matches(line):
                        candidate = {"path": relative, "line": number, "text": line[:500]}
                        break
            except OSError:
                pass
        if candidate is not None:
            if len(results) >= match_limit:
                return {"query": query, "regex": pattern is not None, "matches": results, "truncated": True}
            results.append(candidate)
    return {"query": query, "regex": pattern is not None, "matches": results, "truncated": False}


TOOL_FUNCTIONS = {"list_files": _list_files, "read_file": _read_file, "write_file": _write_file, "edit_file": _edit_file, "move_file": _move_file, "archive_file": _archive_file, "search_files": _search_files, "run_command": _run_command_stream, "web_search": _web_search}
BUDGET_RESET_TOOLS = frozenset({"write_file", "edit_file", "move_file", "archive_file", "run_command"})
MAX_TOOL_SIGNATURES = max(16, MAX_REPEATED_TOOL_CALLS * 8)
TRUNCATED_FINISH_REASONS = frozenset({"length", "max_tokens", "max_output_tokens"})


def _tool_call_signature(name: str, arguments: str) -> str:
    try:
        normalized = json.dumps(json.loads(arguments or "{}"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        normalized = str(arguments or "")
    return name + "\x00" + normalized


def _has_repeating_tool_cycle(signatures: list[str]) -> bool:
    repetitions = MAX_REPEATED_TOOL_CALLS
    max_cycle_length = min(4, len(signatures) // repetitions)
    for cycle_length in range(1, max_cycle_length + 1):
        pattern = signatures[-cycle_length:]
        if signatures[-cycle_length * repetitions:] == pattern * repetitions:
            return True
    return False


def _finish_reason(value: Any) -> str:
    normalized = str(getattr(value, "value", value) or "").casefold()
    return normalized.rsplit(".", 1)[-1]


def _tool_summary(name: str, arguments: str) -> str:
    try:
        data = json.loads(arguments or "{}")
    except (TypeError, ValueError):
        data = {}

    def value(key: str, fallback: str = "") -> str:
        raw = data.get(key, fallback) if isinstance(data, dict) else fallback
        return _redact(str(raw).strip())[:160]

    labels = {
        "list_files": "Listando archivos",
        "read_file": "Leyendo archivo",
        "write_file": "Escribiendo archivo",
        "edit_file": "Editando archivo",
        "move_file": "Moviendo archivo",
        "archive_file": "Archivando archivo",
        "search_files": "Buscando archivos",
        "run_command": "Ejecutando comando",
        "web_search": "Buscando en Internet",
    }
    label = labels.get(name, f"Ejecutando {name}")
    if name in {"list_files", "read_file", "write_file", "edit_file", "archive_file"}:
        path = value("path")
        if path:
            return f"{label} [{path}]"
    if name == "move_file":
        source, destination = value("source"), value("destination")
        if source or destination:
            return f"{label} [{source}] → [{destination}]"
    if name in {"search_files", "web_search"}:
        query = value("query")
        if query:
            return f'{label} "{query}"'
    return label


def _serialize_tool_result(result: Any) -> str:
    output = _redact(json.dumps(result, ensure_ascii=False))
    if len(output) <= 50_000:
        return output
    return json.dumps({"truncated": True, "original_chars": len(output), "preview": output[:20_000]}, ensure_ascii=False)


def _execute_tool(name: str, arguments: str) -> dict[str, Any]:
    if name == "run_command":
        return {"ok": False, "error": "run_command requiere el contexto asíncrono de una ejecución."}
    function = TOOL_FUNCTIONS.get(name)
    if function is None:
        return {"ok": False, "error": f"Herramienta desconocida: {name}"}
    try:
        parsed = json.loads(arguments or "{}")
        result = function(**parsed)
        return {"ok": True, "result": _serialize_tool_result(result)}
    except Exception as exc:
        return {"ok": False, "error": _redact(str(exc))}


async def _execute_tool_async(run: Run, name: str, arguments: str) -> dict[str, Any]:
    return await _run_command_stream(run, arguments) if name == "run_command" else await asyncio.to_thread(_execute_tool, name, arguments)


def _close_model_stream(run: Run) -> None:
    with run.stream_lock:
        stream, run.stream = run.stream, None
    if stream is not None and callable(getattr(stream, "close", None)):
        try:
            stream.close()
        except Exception:
            pass


def _stream_worker(run: Run, messages: list[dict[str, Any]], events: queue.Queue[tuple[str, Any]] | None = None) -> None:
    if events is None:
        events = run.thread_events
    if client is None:
        events.put(("failure", "OPENROUTER_API_KEY no configurada"))
        return
    try:
        request = {"model": run.model, "messages": messages, "stream": True}
        if not run.chat_only:
            request["tools"] = TOOLS
        stream = client.chat.send(**request)
        with run.stream_lock:
            run.stream = stream
        parts, calls, finish_reason = [], {}, ""
        for chunk in stream:
            if run.stop.is_set():
                break
            choices = getattr(chunk, "choices", None) or []
            if not choices:
                continue
            choice = choices[0]
            current_finish_reason = _finish_reason(getattr(choice, "finish_reason", None))
            if current_finish_reason:
                finish_reason = current_finish_reason
            delta = getattr(choice, "delta", None)
            if delta is None:
                continue
            text = getattr(delta, "content", "") or ""
            if text:
                text = str(text)
                parts.append(text)
                events.put(("chunk", text))
            for item in getattr(delta, "tool_calls", None) or []:
                index = int(getattr(item, "index", 0) or 0)
                function = getattr(item, "function", None)
                current = calls.setdefault(index, {"id": "", "name": "", "arguments": ""})
                fragment_id = str(getattr(item, "id", "") or "")
                fragment_name = str(getattr(function, "name", "") or "")
                if fragment_id and not current["id"]:
                    current["id"] = fragment_id
                if fragment_name and not current["name"]:
                    current["name"] = fragment_name
                current["arguments"] += str(getattr(function, "arguments", "") or "")
        events.put(("complete", {"text": "".join(parts), "tool_calls": list(calls.values()), "finish_reason": finish_reason}))
    except Exception as exc:
        events.put(("complete", {"text": "", "tool_calls": [], "finish_reason": "cancelled"}) if run.stop.is_set() else ("failure", _redact(str(exc))))
    finally:
        _close_model_stream(run)


def _guarded_stream_worker(run: Run, messages: list[dict[str, Any]], events: queue.Queue[tuple[str, Any]] | None = None) -> None:
    if events is None:
        with run.thread_events_lock:
            events = run.thread_events
    try:
        with run.thread_events_lock:
            _stream_worker(run, messages, events)
    except BaseException as exc:
        events.put(("failure", "El stream falló: " + _redact(str(exc) or type(exc).__name__)))
    finally:
        events.put(("worker_exit", None))


def _compact_agent_messages(messages: list[dict[str, Any]], base_count: int) -> None:
    """Limita resultados de herramientas y conserva solo los turnos recientes."""
    dynamic = messages[base_count:]
    if not dynamic:
        return
    for message in dynamic:
        if message.get("role") != "tool":
            continue
        content = str(message.get("content", ""))
        if len(content) > MAX_AGENT_TOOL_CHARS:
            message["content"] = content[:MAX_AGENT_TOOL_CHARS] + "\n[…resultado truncado…]"

    current_start = next(
        (index for index in range(len(dynamic) - 1, -1, -1) if dynamic[index].get("role") == "assistant" and dynamic[index].get("tool_calls")),
        len(dynamic),
    )
    previous = dynamic[:current_start]
    current = dynamic[current_start:]
    while previous and sum(len(str(item.get("content", ""))) + 120 for item in messages[:base_count] + previous + current) > MAX_AGENT_MESSAGE_CHARS:
        end = 1
        while end < len(previous) and previous[end].get("role") == "tool":
            end += 1
        del previous[:end]
    messages[base_count:] = previous + current


async def _emit(run: Run, event_type: str, data: Any) -> None:
    if event_type != "token":
        log_data = data
        if event_type == "done" and isinstance(data, dict):
            log_data = {key: data[key] for key in ("elapsed", "chars", "segments", "truncated", "finish_reason") if key in data}
        elif event_type == "tool_end" and isinstance(data, dict):
            log_data = {key: data[key] for key in ("name", "call_id", "ok", "step", "steps_remaining", "budget_reset") if key in data}
        print(f"[{event_type.upper()}] {_redact(json.dumps(log_data, ensure_ascii=False))}", flush=True)
    await run.events.put({"type": event_type, "data": data})


async def _run_agent(run: Run) -> None:
    global active_run
    started = time.perf_counter()
    async with state_lock:
        _trim_history()
        workspace_context = WORKSPACE_CONTEXT
        history_snapshot = [dict(item) for item in history]
    system_content = CHAT_ONLY_SYSTEM_PROMPT if run.chat_only else SYSTEM_PROMPT
    system_content += f"\nPresupuesto de ejecución: {MAX_AGENT_STEPS} steps por tramo y {MAX_TOTAL_AGENT_STEPS} steps totales como límite de seguridad. Tras cada herramienta recibirás execution_progress; prioriza avanzar y no repitas búsquedas sin resultados."
    messages = [{"role": "system", "content": system_content}]
    if workspace_context and not run.chat_only:
        messages.append({"role": "system", "content": workspace_context})
    messages.extend(history_snapshot)
    messages.append({"role": "user", "content": run.message})
    agent_context_start = len(messages)
    await _emit(run, "status", {"status": "thinking", "run_id": run.run_id, "step": 0, "steps_remaining": MAX_AGENT_STEPS, "total_steps": 0, "max_steps": MAX_AGENT_STEPS, "max_total_steps": MAX_TOTAL_AGENT_STEPS})
    print("[USER] " + _redact(run.message), flush=True)
    tool_signatures: list[str] = []
    reply_segments: list[str] = []
    response_segment = 1
    step = 0
    total_steps = 0
    try:
        while total_steps < MAX_TOTAL_AGENT_STEPS and step < MAX_AGENT_STEPS:
            step += 1
            total_steps += 1
            if total_steps > 1:
                await _emit(run, "status", {"status": "thinking", "run_id": run.run_id, "step": step, "steps_remaining": max(0, MAX_AGENT_STEPS - step), "total_steps": total_steps, "max_steps": MAX_AGENT_STEPS, "max_total_steps": MAX_TOTAL_AGENT_STEPS})
            if run.stop.is_set():
                await _emit(run, "cancelled", {"run_id": run.run_id})
                return
            with run.thread_events_lock:
                run.thread_events = queue.Queue()
                thread_events = run.thread_events
            threading.Thread(target=_guarded_stream_worker, args=(run, messages, thread_events), daemon=True).start()
            chunks, complete = [], None
            while complete is None:
                if run.stop.is_set():
                    _close_model_stream(run)
                    await _emit(run, "cancelled", {"run_id": run.run_id})
                    return
                try:
                    kind, value = thread_events.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(.03)
                    continue
                if kind == "chunk":
                    chunks.append(value)
                    await _emit(run, "token", {"text": value})
                elif kind == "failure":
                    await _emit(run, "failure", {"message": value})
                    return
                elif kind == "complete":
                    complete = value
                elif kind == "worker_exit":
                    await _emit(run, "failure", {"message": "El stream terminó sin emitir un resultado final."})
                    return
                else:
                    await _emit(run, "failure", {"message": f"Evento interno de stream desconocido: {kind}"})
                    return
            calls = complete.get("tool_calls", [])
            if calls:
                assistant_calls = []
                for index, call in enumerate(calls):
                    call_id = call.get("id") or f"call_{run.run_id[:8]}_{step}_{index}"
                    assistant_calls.append({"id": call_id, "type": "function", "function": {"name": call.get("name", ""), "arguments": call.get("arguments", "{}")}})
                messages.append({"role": "assistant", "content": "", "tool_calls": assistant_calls})
                if run.chat_only:
                    await _emit(run, "failure", {"message": "El modo SOLO CHAT no permite herramientas."})
                    return
                await _emit(run, "status", {"status": "executing", "step": step, "steps_remaining": max(0, MAX_AGENT_STEPS - step), "total_steps": total_steps, "max_steps": MAX_AGENT_STEPS, "max_total_steps": MAX_TOTAL_AGENT_STEPS})
                for call in assistant_calls:
                    name = call["function"]["name"]
                    arguments = call["function"]["arguments"]
                    tool_signatures.append(_tool_call_signature(name, arguments))
                    del tool_signatures[:-MAX_TOOL_SIGNATURES]
                    if _has_repeating_tool_cycle(tool_signatures):
                        await _emit(run, "failure", {"message": "Se detectó un ciclo repetido de herramientas; se detuvo la ejecución."})
                        return
                    await _emit(run, "tool_start", {"name": name, "call_id": call["id"], "summary": _tool_summary(name, arguments), "step": step, "steps_remaining": max(0, MAX_AGENT_STEPS - step), "total_steps": total_steps, "max_steps": MAX_AGENT_STEPS})
                    if name == "run_command":
                        await _emit(run, "command_start", {"cwd": str(WORKSPACE_ROOT), "call_id": call["id"]})
                    result = await _execute_tool_async(run, name, arguments)
                    budget_reset = result.get("ok") is True and name in BUDGET_RESET_TOOLS
                    if budget_reset:
                        step = 0
                    await _emit(run, "tool_end", {"name": name, "call_id": call["id"], **result, "step": step, "steps_remaining": max(0, MAX_AGENT_STEPS - step), "total_steps": total_steps, "max_steps": MAX_AGENT_STEPS, "budget_reset": budget_reset})
                    progress = {"step": step, "steps_remaining": max(0, MAX_AGENT_STEPS - step), "total_steps": total_steps, "max_steps": MAX_AGENT_STEPS, "max_total_steps": MAX_TOTAL_AGENT_STEPS, "budget_reset": budget_reset}
                    tool_message = {**result, "execution_progress": progress}
                    messages.append({"role": "tool", "tool_call_id": call["id"], "content": json.dumps(tool_message, ensure_ascii=False)})
                    if budget_reset:
                        await _emit(run, "status", {"status": "budget_reset", "reason": name, "step": 0, "steps_remaining": MAX_AGENT_STEPS, "total_steps": total_steps, "max_steps": MAX_AGENT_STEPS, "max_total_steps": MAX_TOTAL_AGENT_STEPS})
                _compact_agent_messages(messages, agent_context_start)
                continue
            segment = "".join(chunks) or str(complete.get("text", ""))
            finish_reason = _finish_reason(complete.get("finish_reason"))
            if finish_reason in TRUNCATED_FINISH_REASONS and response_segment < MAX_RESPONSE_SEGMENTS and segment:
                reply_segments.append(segment)
                messages.extend([
                    {"role": "assistant", "content": segment},
                    {"role": "user", "content": "Continúa exactamente donde terminó tu respuesta. No repitas texto y completa únicamente lo pendiente."},
                ])
                response_segment += 1
                await _emit(run, "status", {"status": "continuing", "segment": response_segment, "max_segments": MAX_RESPONSE_SEGMENTS, "step": step, "steps_remaining": max(0, MAX_AGENT_STEPS - step), "total_steps": total_steps})
                continue
            reply = "".join(reply_segments + [segment]).strip() or "(El modelo no devolvió texto.)"
            truncated = finish_reason in TRUNCATED_FINISH_REASONS
            async with state_lock:
                history.extend([{"role": "user", "content": run.message}, {"role": "assistant", "content": reply}])
                _trim_history()
                _save_conversation()
            await _emit(run, "done", {"reply": reply, "elapsed": round(time.perf_counter() - started, 3), "chars": len(reply), "segments": response_segment, "truncated": truncated, "finish_reason": finish_reason})
            return
        if total_steps >= MAX_TOTAL_AGENT_STEPS:
            message = f"Se alcanzó GCA_MAX_TOTAL_STEPS={MAX_TOTAL_AGENT_STEPS}."
        else:
            message = f"Se alcanzó el presupuesto de {MAX_AGENT_STEPS} steps sin una herramienta exitosa que lo recargara."
        await _emit(run, "failure", {"message": message, "step": step, "steps_remaining": max(0, MAX_AGENT_STEPS - step), "total_steps": total_steps, "max_steps": MAX_AGENT_STEPS, "max_total_steps": MAX_TOTAL_AGENT_STEPS})
    except Exception as exc:
        await _emit(run, "failure", {"message": "Error interno del agente: " + _redact(str(exc))})
    finally:
        run.done = True
        run.finished.set()
        async with run_lock:
            if active_run is run:
                active_run = None


def _prune_runs() -> None:
    with runs_lock:
        completed = [key for key, item in runs.items() if item.done]
        for key in completed[:max(0, len(runs) - MAX_RETAINED_RUNS)]:
            runs.pop(key, None)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>PicoUno</title>
<style>
:root{color-scheme:dark;--bg:#080b14;--panel:#111827;--panel-2:#0d1322;--line:#26324a;--text:#e8edf7;--muted:#8e9ab1;--accent:#8b5cf6;--accent-2:#22d3ee;--ok:#34d399;--danger:#fb7185}
*{box-sizing:border-box}
body{max-width:980px;margin:0 auto;padding:1.25rem;background:radial-gradient(circle at 80% -10%,#1c1640 0,#080b14 42rem);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}
.shell{display:grid;gap:1rem}
header,.panel-heading,.actions,.model-row,.composer-actions{display:flex;align-items:center;gap:.75rem}
header{justify-content:space-between;padding:.5rem .25rem}
.eyebrow{margin:0 0 .25rem;color:var(--accent-2);font-size:.7rem;font-weight:800;letter-spacing:.14em}
h1,h2,p{margin:0}h1{font-size:clamp(1.35rem,3vw,2rem);letter-spacing:-.03em}h2{font-size:1rem}
#status{color:var(--muted);font-size:.82rem;font-weight:500}
.mode-badge{border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:.72rem;font-weight:800;letter-spacing:.08em;padding:.38rem .7rem;text-transform:uppercase}
.mode-badge.active{border-color:#6d4bd6;background:#291b5b;color:#d9ceff}
.mode-badge.chat{border-color:#0e7490;background:#083344;color:#a5f3fc}
.panel{border:1px solid var(--line);border-radius:14px;background:linear-gradient(145deg,rgba(17,24,39,.96),rgba(13,19,34,.96));box-shadow:0 16px 45px rgba(0,0,0,.18);padding:1rem}
.panel-heading{justify-content:space-between;margin-bottom:.85rem}
.field{display:grid;gap:.38rem;color:var(--muted);font-size:.78rem;font-weight:700;letter-spacing:.02em}
input,textarea,select{width:100%;border:1px solid #34415d;border-radius:9px;background:#0b1120;color:var(--text);font:inherit;outline:none;padding:.7rem .78rem;transition:border-color .15s,box-shadow .15s}
input:focus,textarea:focus,select:focus{border-color:var(--accent-2);box-shadow:0 0 0 3px rgba(34,211,238,.12)}
input:disabled{color:#6b7890;background:#0d1422}
.actions{flex-wrap:wrap;margin-top:.8rem}
button{border:1px solid #3a4968;border-radius:9px;background:#172238;color:var(--text);cursor:pointer;font:600 .82rem inherit;padding:.66rem .85rem;transition:transform .15s,border-color .15s,background .15s}
button:hover:not(:disabled){border-color:#8ea1c5;background:#20304b;transform:translateY(-1px)}
button:disabled{cursor:not-allowed;opacity:.48}
button.primary{border-color:#7653db;background:#4c2ca7}
button.primary:hover:not(:disabled){background:#5b38c4}
button.secondary{border-color:#0e7490;background:#0c3b4d}
button.ghost{background:transparent}
[hidden]{display:none!important}
.workspace-status{min-height:1.25rem;margin-top:.75rem;color:var(--muted);font-size:.8rem}
.context-panel.compact{padding:.85rem 1rem}.context-panel.compact .actions{margin-top:0}.context-panel.compact .workspace-status{margin-top:.6rem}
.model-row{align-items:flex-end;flex-wrap:wrap}
.model-field{flex:1 1 24rem}
#models-status{align-self:center;color:var(--muted);font-size:.75rem}
#chat{min-height:390px;max-height:60vh;overflow:auto;border:1px solid var(--line);border-radius:14px;background:#050811;padding:1rem}
.msg,.event{overflow-wrap:anywhere;margin:.7rem 0;border-radius:10px;padding:.72rem .82rem}
.user,.event{white-space:pre-wrap}
.msg{line-height:1.5}.user{margin-left:12%;background:#182d52;border:1px solid #274b80}.assistant{margin-right:12%;background:#151f31;border:1px solid #2b3a55}
.msg-author{display:block;margin-bottom:.35rem;color:#9fb0ca;font-size:.68rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
.message-body>*:first-child{margin-top:0}.message-body>*:last-child{margin-bottom:0}
.message-body p,.message-body ul,.message-body ol,.message-body blockquote,.message-body pre,.message-body table{margin:.65rem 0}
.message-body h1,.message-body h2,.message-body h3,.message-body h4{margin:1rem 0 .45rem;color:#f5f3ff;line-height:1.25}
.message-body h1{font-size:1.35rem}.message-body h2{font-size:1.18rem}.message-body h3{font-size:1.04rem}.message-body h4{font-size:.95rem}
.message-body ul,.message-body ol{padding-left:1.4rem}.message-body li+li{margin-top:.25rem}
.message-body code{border:1px solid #34415d;border-radius:5px;background:#090e1a;color:#b9f4ff;font:.86em ui-monospace,SFMono-Regular,Consolas,monospace;padding:.1rem .3rem}
.message-body pre{overflow:auto;border:1px solid #34415d;border-radius:9px;background:#080c16;padding:.8rem}.message-body pre code{border:0;background:transparent;padding:0;white-space:pre}
.message-body blockquote{border-left:3px solid var(--accent);color:#bdc8db;padding:.15rem 0 .15rem .8rem}
.message-body a{color:#67e8f9;text-decoration-color:#155e75;text-underline-offset:2px}
.message-body hr{border:0;border-top:1px solid var(--line);margin:1rem 0}
.message-body table{display:block;max-width:100%;overflow:auto;border-collapse:collapse;font-size:.9rem}.message-body th,.message-body td{border:1px solid #34415d;padding:.45rem .6rem;text-align:left}.message-body th{background:#101a2c;color:#e9e5ff}
.event{border-left:3px solid #52617c;background:#0d1422;color:#aab6ca;font: .78rem ui-monospace,SFMono-Regular,Consolas,monospace}
.event.execution{border-left-color:var(--accent);color:#cfc2ff}.event.execution.command,.event.execution.streaming{border-left-color:var(--accent-2);color:#a5f3fc}.event.execution.done{border-left-color:var(--ok);color:#a7f3d0}.event.execution.error{border-left-color:var(--danger);color:#fecdd3}.event.execution.thinking::before,.event.execution.tool::before,.event.execution.command::before,.event.execution.streaming::before{content:'●';display:inline-block;margin-right:.55rem;animation:pulse 1s ease-in-out infinite}.event.error{border-left-color:var(--danger);color:#fecdd3}
@keyframes pulse{50%{opacity:.25}}
.composer{display:grid;gap:.7rem}.composer-actions{justify-content:flex-end}
#msg{min-height:90px;resize:vertical}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap}
@media (max-width:640px){body{padding:.75rem}.panel{padding:.8rem}.user,.assistant{margin-left:0;margin-right:0}header{align-items:flex-start;gap:.5rem;flex-direction:column}.mode-badge{align-self:flex-start}.model-field{flex-basis:100%}}
</style>
</head>
<body>
<div class="shell">
<header><div><p class="eyebrow">AGENTE LOCAL</p><h1>PicoUno <span id="status">· elige carpeta</span></h1></div><span id="mode-badge" class="mode-badge">Sin conversación</span></header>
<section id="context-panel" class="panel context-panel" aria-label="Contexto">
<div id="context-heading" class="panel-heading"><h2>Contexto</h2></div>
<label id="workspace-field" class="field">Carpeta de trabajo<input id="workspace" placeholder="C:\\proyectos\\mi-app"></label>
<div class="actions"><button id="select-folder" class="primary">Seleccionar carpeta…</button><button id="chat-only" class="ghost">SOLO CHAT</button><button id="new" class="secondary" hidden>Nueva conversación</button></div>
<div id="workspace-status" class="workspace-status">Selecciona una carpeta o activa SOLO CHAT.</div>
</section>
<section class="panel" aria-labelledby="model-title">
<div class="panel-heading"><h2 id="model-title">Modelo</h2><span id="models-status">Cargando…</span></div>
<div id="model-controls" class="model-row"><label class="field model-field"><span class="sr-only">Modelo</span><select id="model"></select></label><button id="refresh">Actualizar modelos</button></div>
</section>
<main id="chat" aria-live="polite"></main>
<section class="panel composer"><textarea id="msg" placeholder="Escribe un mensaje…"></textarea><div class="composer-actions"><button id="stop" disabled>Detener</button><button id="send" class="primary" disabled>Enviar</button></div></section>
</div>
<script>
const q=s=>document.querySelector(s),chat=q('#chat'),msg=q('#msg'),status=q('#status'),send=q('#send'),stop=q('#stop'),model=q('#model'),workspace=q('#workspace'),wsStatus=q('#workspace-status'),modeBadge=q('#mode-badge'),contextPanel=q('#context-panel'),contextHeading=q('#context-heading'),workspaceField=q('#workspace-field'),selectFolderButton=q('#select-folder'),chatOnlyButton=q('#chat-only'),newButton=q('#new'),refreshButton=q('#refresh'),modelsStatus=q('#models-status');
let source=null,authenticating=null,currentMode='none',executionNode=null,responseNode=null,responseText='',streamFailures=0,renderFrame=null;
function appendInline(parent,text){
  let index=0,plain='';
  const flush=()=>{if(plain){parent.append(document.createTextNode(plain));plain=''}};
  const styled=(tag,value)=>{flush();const node=document.createElement(tag);appendInline(node,value);parent.append(node)};
  while(index<text.length){
    const pairs=[['**','**','strong'],['__','__','strong'],['~~','~~','del'],['`','`','code'],['*','*','em']];
    let matched=false;
    for(const [open,close,tag] of pairs){if(!text.startsWith(open,index))continue;const end=text.indexOf(close,index+open.length);if(end<index+open.length)continue;styled(tag,text.slice(index+open.length,end));index=end+close.length;matched=true;break}
    if(matched)continue;
    if(text[index]==='['){const labelEnd=text.indexOf('](',index+1),urlEnd=labelEnd<0?-1:text.indexOf(')',labelEnd+2);if(labelEnd>index&&urlEnd>labelEnd){const url=text.slice(labelEnd+2,urlEnd);if(url.startsWith('https://')||url.startsWith('http://')){flush();const link=document.createElement('a');link.href=url;link.target='_blank';link.rel='noopener noreferrer';appendInline(link,text.slice(index+1,labelEnd));parent.append(link);index=urlEnd+1;continue}}}
    plain+=text[index++];
  }
  flush();
}
function markdownCells(line){let value=line.trim();if(value.startsWith('|'))value=value.slice(1);if(value.endsWith('|'))value=value.slice(0,-1);return value.split('|').map(cell=>cell.trim())}
function tableDivider(line){const cells=markdownCells(line);return cells.length>0&&cells.every(cell=>{let core=cell;if(core.startsWith(':'))core=core.slice(1);if(core.endsWith(':'))core=core.slice(0,-1);return core.length>=3&&[...core].every(char=>char==='-')})}
function heading(line){let level=0;while(level<4&&line[level]==='#')level++;return level&&line[level]===' '?[level,line.slice(level+1)]:null}
function bullet(line){for(const mark of ['- ','* ','+ '])if(line.startsWith(mark))return line.slice(2);return null}
function ordered(line){const dot=line.indexOf('.');if(dot<1||line[dot+1]!==' ')return null;return [...line.slice(0,dot)].every(char=>char>='0'&&char<='9')?line.slice(dot+2):null}
function startsBlock(lines,index){const line=lines[index]||'';return !line.trim()||line.startsWith('```')||heading(line)||['---','***','___'].includes(line.trim())||line.startsWith('> ')||bullet(line)!==null||ordered(line)!==null||(line.includes('|')&&index+1<lines.length&&tableDivider(lines[index+1]))}
function renderMarkdown(target,markdown){
  const lines=String(markdown||'').replaceAll('\\r\\n','\\n').split('\\n'),fragment=document.createDocumentFragment();let index=0;
  while(index<lines.length){
    const line=lines[index];if(!line.trim()){index++;continue}
    if(line.startsWith('```')){const language=line.slice(3).trim(),code=[];index++;while(index<lines.length&&!lines[index].startsWith('```'))code.push(lines[index++]);if(index<lines.length)index++;const pre=document.createElement('pre'),node=document.createElement('code');if(language)node.dataset.language=language;node.textContent=code.join('\\n');pre.append(node);fragment.append(pre);continue}
    const title=heading(line);if(title){const node=document.createElement('h'+title[0]);appendInline(node,title[1]);fragment.append(node);index++;continue}
    if(['---','***','___'].includes(line.trim())){fragment.append(document.createElement('hr'));index++;continue}
    if(line.includes('|')&&index+1<lines.length&&tableDivider(lines[index+1])){const headers=markdownCells(line),alignment=markdownCells(lines[index+1]),table=document.createElement('table'),head=document.createElement('thead'),headRow=document.createElement('tr');headers.forEach((cell,column)=>{const node=document.createElement('th');appendInline(node,cell);const rule=alignment[column]||'';if(rule.startsWith(':')&&rule.endsWith(':'))node.style.textAlign='center';else if(rule.endsWith(':'))node.style.textAlign='right';headRow.append(node)});head.append(headRow);table.append(head);index+=2;const body=document.createElement('tbody');while(index<lines.length&&lines[index].includes('|')&&lines[index].trim()){const row=document.createElement('tr');markdownCells(lines[index]).forEach((cell,column)=>{const node=document.createElement('td');appendInline(node,cell);const rule=alignment[column]||'';if(rule.startsWith(':')&&rule.endsWith(':'))node.style.textAlign='center';else if(rule.endsWith(':'))node.style.textAlign='right';row.append(node)});body.append(row);index++}table.append(body);fragment.append(table);continue}
    if(line.startsWith('> ')){const node=document.createElement('blockquote'),parts=[];while(index<lines.length&&lines[index].startsWith('> '))parts.push(lines[index++].slice(2));appendInline(node,parts.join(' '));fragment.append(node);continue}
    const firstBullet=bullet(line),firstOrdered=ordered(line);if(firstBullet!==null||firstOrdered!==null){const orderedList=firstOrdered!==null,node=document.createElement(orderedList?'ol':'ul');while(index<lines.length){const value=orderedList?ordered(lines[index]):bullet(lines[index]);if(value===null)break;const item=document.createElement('li');appendInline(item,value);node.append(item);index++}fragment.append(node);continue}
    const paragraph=document.createElement('p'),parts=[line];index++;while(index<lines.length&&!startsBlock(lines,index))parts.push(lines[index++]);appendInline(paragraph,parts.join(' '));fragment.append(paragraph);
  }
  target.replaceChildren(fragment);
}
function add(role,text){const e=document.createElement('div'),author=document.createElement('span'),body=document.createElement('div');e.className='msg '+role;author.className='msg-author';author.textContent=role==='user'?'Usted':'PicoUno';body.className='message-body';if(role==='assistant')renderMarkdown(body,text);else body.textContent=text;e.append(author,body);chat.append(e);chat.scrollTop=chat.scrollHeight;return e}function event(kind,text){const e=document.createElement('div');e.className='event '+kind;e.textContent=text;chat.append(e);chat.scrollTop=chat.scrollHeight}
function updateExecution(kind,text){if(!executionNode){executionNode=document.createElement('div');chat.append(executionNode)}executionNode.className='event execution '+kind;executionNode.textContent='Ejecución · '+text;chat.scrollTop=chat.scrollHeight}
function renderStreamedReply(){renderFrame=null;if(responseNode)renderMarkdown(responseNode.querySelector('.message-body'),responseText);chat.scrollTop=chat.scrollHeight}
function resetStreamedReply(remove){if(renderFrame)cancelAnimationFrame(renderFrame);renderFrame=null;if(remove&&responseNode)responseNode.remove();responseNode=null;responseText=''}
function appendToken(text){if(!responseNode)responseNode=add('assistant','');responseText+=text;if(!renderFrame)renderFrame=requestAnimationFrame(renderStreamedReply)}
function completeReply(reply){if(!responseNode)responseNode=add('assistant','');responseText=reply;if(renderFrame)cancelAnimationFrame(renderFrame);renderStreamedReply();responseNode=null;responseText=''}
function setConversationControls(active){selectFolderButton.hidden=active;chatOnlyButton.hidden=active;newButton.hidden=!active}
function setContextCompact(compact){contextHeading.hidden=compact;workspaceField.hidden=compact;contextPanel.classList.toggle('compact',compact)}
function setModelLocked(locked){model.disabled=locked;refreshButton.hidden=locked;modelsStatus.hidden=locked}
function setMode(mode){currentMode=mode;const chatOnly=mode==='chat',workspaceMode=mode==='workspace',ready=chatOnly||workspaceMode;workspace.disabled=chatOnly||workspaceMode;modeBadge.className='mode-badge '+(chatOnly?'chat':workspaceMode?'active':'');modeBadge.textContent=chatOnly?'Solo chat':workspaceMode?'Carpeta activa':mode==='choosing'?'Elige modo':'Sin conversación';if(!source){status.textContent=ready?'· listo':'· elige modo';send.disabled=!ready}}
async function login(){const token=prompt('Token de acceso de PicoUno:');if(!token)return false;const r=await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});return r.ok}async function apiFetch(url,options){const r=await fetch(url,options);if(r.status!==401)return r;if(!authenticating)authenticating=login();const ok=await authenticating;authenticating=null;return ok?fetch(url,options):r}
async function models(refresh){const r=await apiFetch('/api/models'+(refresh?'?refresh=true':'')),d=await r.json();if(r.ok){model.replaceChildren(...d.models.map(x=>new Option((x.name||x.id)+' ('+x.id+')',x.id)));model.value=d.selected;if(model.selectedIndex<0&&model.options.length)model.selectedIndex=0;modelsStatus.textContent=d.models.length+' modelos'+(d.cached?' · caché':'')}else modelsStatus.textContent=d.detail||'No disponible'}
function prepareConversation(){if(source)return;if(chat.childElementCount&&!confirm('¿Crear una conversación nueva? Se borrará la conversación actual.'))return;setConversationControls(false);setContextCompact(false);setModelLocked(false);setMode('choosing');wsStatus.textContent='Selecciona una carpeta o activa SOLO CHAT.'}
async function selectFolder(){wsStatus.textContent='Abriendo selector de carpetas…';const r=await apiFetch('/api/workspace/select'),d=await r.json();if(!r.ok){wsStatus.textContent=d.detail||'No se pudo abrir el selector';return}if(d.cancelled){wsStatus.textContent='Selección cancelada.';return}workspace.value=d.workspace;await conversation()}
async function conversation(){if(!workspace.value.trim()){wsStatus.textContent='Selecciona una carpeta primero.';return}const r=await apiFetch('/api/conversation',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({workspace:workspace.value,files:[]})}),d=await r.json();if(!r.ok){wsStatus.textContent=d.detail;return}chat.replaceChildren();executionNode=null;resetStreamedReply(true);setConversationControls(true);setContextCompact(false);setModelLocked(false);setMode('workspace');wsStatus.textContent='Activa: '+d.workspace}
async function startChatOnly(){const r=await apiFetch('/api/conversation/chat-only',{method:'POST'}),d=await r.json();if(!r.ok){wsStatus.textContent=d.detail||'No se pudo activar SOLO CHAT';return}chat.replaceChildren();executionNode=null;resetStreamedReply(true);workspace.value='';setConversationControls(true);setContextCompact(false);setModelLocked(false);setMode('chat');wsStatus.textContent='SOLO CHAT activo · no se envían carpeta ni herramientas'}
async function restoreConversation(){const r=await apiFetch('/api/conversation'),d=await r.json();if(!r.ok||!d.active){setConversationControls(false);setContextCompact(false);setModelLocked(false);setMode('choosing');return}chat.replaceChildren();d.history.forEach(x=>add(x.role,x.content));setConversationControls(true);setContextCompact(d.messages>0);setModelLocked(d.messages>0);if(d.mode==='chat'){workspace.value='';setMode('chat');wsStatus.textContent='SOLO CHAT activo · no se envían carpeta ni herramientas'}else{workspace.value=d.workspace;setMode('workspace');wsStatus.textContent='Activa: '+d.workspace}}
function parseResult(value){if(typeof value!=='string')return value;try{return JSON.parse(value)}catch(_){return null}}
function toolResultText(d){if(!d.ok)return d.error||'La herramienta falló';const result=parseResult(d.result)||{};if(d.name==='run_command'){const code=result.return_code==null?'?':result.return_code,elapsed=result.elapsed===undefined?'?':result.elapsed;return 'Comando terminado · código '+code+' · '+elapsed+' s'+(result.timed_out?' · timeout':'')+(result.cancelled?' · cancelado':'')}if(d.name==='read_file')return 'Archivo leído'+(result.path?' ['+result.path+']':'');if(d.name==='write_file')return 'Archivo escrito'+(result.path?' ['+result.path+']':'');if(d.name==='edit_file')return 'Archivo editado'+(result.path?' ['+result.path+']':'')+' · '+(result.replacements||0)+' reemplazo(s)';if(d.name==='move_file')return 'Archivo movido'+(result.destination?' → ['+result.destination+']':'');if(d.name==='archive_file')return 'Archivo archivado'+(result.source?' ['+result.source+']':'');if(d.name==='list_files')return 'Lista completada · '+(result.entries||[]).length+' entradas';if(d.name==='search_files')return 'Búsqueda completada · '+(result.matches||[]).length+' coincidencia(s)'+(result.truncated?' · límite alcanzado':'');if(d.name==='web_search')return 'Búsqueda web completada · '+(result.results||[]).length+' resultado(s)';return 'Herramienta completada'}
function stepSuffix(d){return d.steps_remaining===undefined?'':' · '+d.steps_remaining+' pasos restantes'}
function tool(d,start){if(start){resetStreamedReply(true);updateExecution('tool',(d.summary||('Ejecutando '+d.name))+stepSuffix(d))}else updateExecution(d.ok?'thinking':'error',(d.ok?toolResultText(d):'['+d.name+'] '+toolResultText(d))+(d.budget_reset?' · presupuesto reiniciado ('+(d.max_steps||'?')+' pasos)':'')+(d.ok?' · continuando':''))}
function statusLabel(d){if(d.status==='thinking')return d.step===0?'Pensando · '+d.steps_remaining+' pasos disponibles':'Pensando'+stepSuffix(d);if(d.status==='executing')return 'Ejecutando herramientas'+stepSuffix(d);if(d.status==='budget_reset')return 'Pensando · presupuesto reiniciado · '+d.steps_remaining+' pasos disponibles';if(d.status==='continuing')return 'Continuando respuesta · segmento '+d.segment+'/'+d.max_segments;return d.status+stepSuffix(d)}
function connectStream(runId){streamFailures=0;source=new EventSource('/api/events/'+runId);['status','token','done','cancelled','failure'].forEach(t=>source.addEventListener(t,e=>handle(JSON.parse(e.data))));source.addEventListener('tool_start',e=>tool(JSON.parse(e.data),true));source.addEventListener('tool_end',e=>tool(JSON.parse(e.data),false));source.addEventListener('command_start',e=>{const d=JSON.parse(e.data);updateExecution('command','Comando iniciado'+(d.cwd?' · '+d.cwd:''))});source.addEventListener('command_output',e=>{const d=JSON.parse(e.data);updateExecution('command','Comando · '+(d.line||'').slice(-500))});source.onopen=()=>{status.textContent='· conectado'};source.onerror=()=>{if(!source)return;streamFailures+=1;if(streamFailures<3){updateExecution('thinking','Reconectando streaming · intento '+streamFailures+'/3');status.textContent='· reconectando streaming';return}updateExecution('error','Streaming interrumpido después de 3 intentos.');finish('error')}}
async function sendMessage(){const text=msg.value.trim();if(!text||source)return;if(!['workspace','chat'].includes(currentMode)){event('error','Activa una carpeta o SOLO CHAT antes de enviar.');return}executionNode=null;resetStreamedReply(true);add('user',text);updateExecution('thinking','Conectando con el modelo…');msg.value='';send.disabled=true;stop.disabled=false;try{const r=await apiFetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:text,model:model.value||null})}),d=await r.json();if(!r.ok)throw Error(d.detail);setContextCompact(true);setModelLocked(true);connectStream(d.run_id)}catch(e){msg.value=text;updateExecution('error','Error: '+e.message);finish('error')}}
function handle(d){if(d.status){const label=statusLabel(d);status.textContent='· '+label.toLowerCase();updateExecution(d.status==='executing'?'tool':'thinking',label)}if(d.text){appendToken(d.text);status.textContent='· transmitiendo';updateExecution('streaming','Transmitiendo respuesta · '+responseText.length+' caracteres')}if('reply' in d){completeReply(d.reply);if(d.truncated){updateExecution('error','Respuesta incompleta después de '+d.segments+' segmentos · límite del modelo');finish('respuesta incompleta')}else{updateExecution('done','Completado'+(d.elapsed===undefined?'':' · '+d.elapsed+' s'));finish()}}if(d.message){updateExecution('error',d.message);finish('error')}if(d.run_id&&!('reply' in d)&&!d.text&&!d.status){updateExecution('done','Cancelado');finish('cancelado')}}
function finish(label){if(source){source.close();source=null}send.disabled=!['workspace','chat'].includes(currentMode);stop.disabled=true;if(label)status.textContent='· '+label;else if(currentMode==='chat'||currentMode==='workspace')status.textContent='· listo'}
selectFolderButton.onclick=selectFolder;newButton.onclick=prepareConversation;chatOnlyButton.onclick=startChatOnly;refreshButton.onclick=()=>models(true);send.onclick=sendMessage;stop.onclick=()=>apiFetch('/api/stop/active',{method:'POST'});msg.onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage()}if(e.key==='Escape')stop.click()};models();restoreConversation();
</script>
</body>
</html>"""


@app.post("/api/auth")
def authenticate(request: AuthRequest, response: Response, http_request: Request) -> dict[str, bool]:
    if not ACCESS_TOKEN:
        return {"authenticated": True, "required": False}
    if not secrets.compare_digest(request.token, ACCESS_TOKEN):
        raise HTTPException(401, "Token inválido.")
    response.set_cookie("gca_session", SESSION_TOKEN, max_age=86_400, httponly=True, samesite="strict", secure=http_request.url.scheme == "https")
    return {"authenticated": True, "required": True}


@app.post("/api/chat")
async def start_chat(request: ChatRequest, http_request: Request) -> dict[str, str]:
    global active_run
    if client is None:
        raise HTTPException(503, "Configura OPENROUTER_API_KEY en .env.")
    client_id = http_request.client.host if http_request.client else "unknown"
    retry_after = _consume_chat_rate_limit(client_id)
    if retry_after is not None:
        raise HTTPException(429, "Demasiadas solicitudes de chat.", headers={"Retry-After": str(retry_after)})
    async with run_lock:
        if active_run is not None and not active_run.done:
            raise HTTPException(409, "Ya hay una ejecución activa.")
        async with state_lock:
            chat_only = CHAT_ONLY
            if not WORKSPACE_CONTEXT and not chat_only:
                raise HTTPException(409, "Inicia una conversación y selecciona una carpeta primero.")
        selected_model = request.model.strip() if request.model else MODEL
        if request.model:
            try:
                catalog, _ = await asyncio.to_thread(_fetch_model_catalog)
            except Exception as exc:
                raise HTTPException(502, str(exc)) from exc
            try:
                selected_model = _resolve_model_alias(catalog, selected_model)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        run = Run(uuid.uuid4().hex, request.message.strip(), selected_model, chat_only=chat_only)
        _prune_runs()
        with runs_lock:
            runs[run.run_id] = run
        active_run = run
        asyncio.create_task(_run_agent(run))
    return {"run_id": run.run_id, "model": selected_model}


@app.get("/api/conversation")
async def get_conversation() -> dict[str, Any]:
    async with state_lock:
        mode = "chat" if CHAT_ONLY else "workspace" if WORKSPACE_CONTEXT else None
        return {"active": mode is not None, "mode": mode, "chat_only": CHAT_ONLY, "workspace": str(WORKSPACE_ROOT) if mode == "workspace" else None, "selected_files": list(SELECTED_FILES), "messages": len(history), "history": [dict(item) for item in history]}


@app.post("/api/workspace/inspect")
def inspect_workspace(request: ConversationRequest) -> dict[str, Any]:
    try:
        root = _workspace_path(request.workspace)
        return {"workspace": str(root), **_workspace_listing(root)}
    except (OSError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/workspace/select")
async def select_workspace() -> dict[str, Any]:
    """Abre el selector nativo de carpeta en el equipo local."""
    def choose_folder() -> str:
        import tkinter as tk
        from tkinter import filedialog

        window = tk.Tk()
        try:
            window.withdraw()
            window.attributes("-topmost", True)
            return str(filedialog.askdirectory(title="Selecciona la carpeta de trabajo") or "")
        finally:
            window.destroy()

    try:
        selected = await asyncio.to_thread(choose_folder)
        if not selected:
            return {"cancelled": True}
        workspace = _workspace_path(selected)
        return {"cancelled": False, "workspace": str(workspace), **_workspace_listing(workspace)}
    except Exception as exc:
        raise HTTPException(500, f"No se pudo abrir el selector de carpetas: {exc}") from exc


@app.post("/api/conversation")
async def start_conversation(request: ConversationRequest) -> dict[str, Any]:
    global WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history, active_run
    async with run_lock:
        if active_run is not None and not active_run.done:
            current = active_run
            _request_stop(current)
            try:
                await asyncio.wait_for(current.finished.wait(), timeout=5)
            except TimeoutError as exc:
                raise HTTPException(409, "La ejecución activa no pudo detenerse a tiempo.") from exc
        try:
            root = _workspace_path(request.workspace)
            selected = [str(item).strip() for item in request.files if str(item).strip()]
            context = await asyncio.to_thread(_build_workspace_context, root, selected)
        except (OSError, UnicodeError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        async with state_lock:
            WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history, active_run = root, selected, context, False, [], None
            _save_conversation()
        listing = await asyncio.to_thread(_workspace_listing, root)
    return {"ok": True, "workspace": str(root), "selected_files": list(selected), **listing}


@app.post("/api/conversation/chat-only")
async def start_chat_only() -> dict[str, Any]:
    global WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history, active_run
    async with run_lock:
        if active_run is not None and not active_run.done:
            current = active_run
            _request_stop(current)
            try:
                await asyncio.wait_for(current.finished.wait(), timeout=5)
            except TimeoutError as exc:
                raise HTTPException(409, "La ejecución activa no pudo detenerse a tiempo.") from exc
        async with state_lock:
            WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history, active_run = ROOT, [], "", True, [], None
            _save_conversation()
    return {"ok": True, "mode": "chat", "chat_only": True}


@app.delete("/api/conversation")
async def delete_conversation(request: DeleteConversationRequest) -> dict[str, bool]:
    global WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history, active_run
    if not request.confirmed:
        raise HTTPException(400, "Confirma la eliminación de la conversación.")
    async with run_lock:
        if active_run is not None and not active_run.done:
            current = active_run
            _request_stop(current)
            try:
                await asyncio.wait_for(current.finished.wait(), timeout=5)
            except TimeoutError as exc:
                raise HTTPException(409, "La ejecución activa no pudo detenerse a tiempo.") from exc
        async with state_lock:
            WORKSPACE_ROOT, SELECTED_FILES, WORKSPACE_CONTEXT, CHAT_ONLY, history, active_run = ROOT, [], "", False, [], None
            _save_conversation()
    return {"deleted": True}


@app.get("/api/events/{run_id}")
async def events(run_id: str, request: Request) -> StreamingResponse:
    with runs_lock:
        run = runs.get(run_id)
    if run is None:
        raise HTTPException(404, "Ejecución no encontrada.")
    async def generate():
        yield "retry: 2500\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                item = await asyncio.wait_for(run.events.get(), timeout=15)
            except TimeoutError:
                yield ": keep-alive\n\n"
                continue
            yield f"event: {item['type']}\ndata: {json.dumps(item['data'], ensure_ascii=False)}\n\n"
            if item["type"] in {"done", "failure", "cancelled"}:
                break
    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})


@app.post("/api/stop/{run_id}")
async def stop_chat(run_id: str) -> dict[str, bool]:
    async with run_lock:
        if run_id == "active":
            run = active_run
        else:
            with runs_lock:
                run = runs.get(run_id)
        if run is None or run.done:
            raise HTTPException(404, "No hay una ejecución activa.")
        _request_stop(run)
    return {"stopping": True}


@app.get("/api/models")
async def models(refresh: bool = False) -> dict[str, Any]:
    try:
        catalog, cached = await asyncio.to_thread(_fetch_model_catalog, refresh)
    except Exception as exc:
        raise HTTPException(502, str(exc)) from exc
    with model_catalog_lock:
        fetched_at = model_catalog_fetched_at
    return {"workspace_id": WORKSPACE_ID, "filtered": True, "source": "/api/v1/models/user", "selected": MODEL, "models": catalog, "cached": cached, "fetched_at": fetched_at}


@app.get("/api/health")
def health() -> dict[str, Any]:
    with model_catalog_lock:
        cached_models = len(model_catalog)
    return {"ok": True, "configured": bool(API_KEY), "model": MODEL, "workspace_id": WORKSPACE_ID, "streaming": True, "host": HOST, "port": PORT, "cached_models": cached_models}


if __name__ == "__main__":
    import uvicorn
    if not _is_loopback_host(HOST) and not ACCESS_TOKEN:
        raise SystemExit("GCA_ACCESS_TOKEN es obligatorio cuando GCA_HOST no es loopback.")
    try:
        server_socket = _bind_server_socket(HOST, PORT)
    except OSError as exc:
        raise SystemExit(f"No se puede iniciar PicoUno en {HOST}:{PORT}: {exc}") from exc
    print(f"PicoUno escuchando en http://{HOST}:{PORT}", flush=True)
    print(f"Modelo: {MODEL}", flush=True)
    if not API_KEY:
        print("[WARN] OPENROUTER_API_KEY no está configurada; el servidor sigue disponible.", flush=True)
    try:
        uvicorn.Server(uvicorn.Config(app, host=HOST, port=PORT, log_level="info")).run(sockets=[server_socket])
    finally:
        server_socket.close()
