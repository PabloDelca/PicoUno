# PicoUno · paquete portable

Agente local con UI web, OpenRouter y herramientas para trabajar sobre una carpeta elegida.

| Perfil | Valor |
|---|---|
| 🧠 Modelo | OpenRouter; `openai/gpt-4o-mini` por defecto |
| 🌐 Interfaz | `http://127.0.0.1:8000` |
| 🔒 Comandos | Deshabilitados por defecto |
| ⚠️ `full` | PowerShell con la cuenta del usuario |

## Instalar y arrancar

```powershell
.\setup.ps1
Copy-Item .env.example .env
# Edita .env y añade OPENROUTER_API_KEY
.\start.ps1
```

PicoUno queda en primer plano. Abre `http://127.0.0.1:8000` desde el mismo equipo.

## Modos

| Modo | Carpeta | Herramientas | PowerShell |
|---|---:|---:|---:|
| `SOLO CHAT` | No | No | No |
| Workspace | Sí | Archivos + web | No |
| `full` | Sí | Archivos + web + comando | Sí |

Cada conversación de workspace empieza con una carpeta explícita. Las herramientas de archivos quedan dentro de ella y protegen `.env`, `.git`, `.venv` y `.gca`. Los archivos seleccionados pasan al contexto inicial del modelo.

## Riesgos de `GCA_COMMAND_MODE=full`

> `full` no es un sandbox: el modelo puede solicitar comandos PowerShell y PicoUno los ejecuta sin aprobación por comando.

- PowerShell corre con la cuenta y permisos del usuario.
- El comando no queda limitado al workspace: puede usar rutas absolutas, otras unidades, red, registro, procesos y programas instalados.
- `write_file`, `edit_file` y `move_file` pueden modificar contenido sin copia automática; PowerShell puede además borrar o sobrescribir.
- Archivos, historial y resultados de herramientas pueden enviarse a OpenRouter; las búsquedas web se envían a DuckDuckGo.
- El filtrado de secretos es de mejor esfuerzo. `.env` está protegido por las herramientas de archivos, no por PowerShell.
- Timeout y cancelación actúan sobre el PowerShell directo; un proceso hijo podría continuar.
- Si `GCA_HOST` no es loopback, `GCA_ACCESS_TOKEN` es obligatorio. No hay TLS integrado.

Deja `GCA_COMMAND_MODE=disabled` para mantener el modo sin ejecución de comandos. Para probar `full`, usa un workspace separado y sin secretos.

## Configuración rápida

Consulta [`.env.example`](.env.example). Las variables más importantes son:

```dotenv
OPENROUTER_API_KEY=sk-...
OPENROUTER_MODEL=openai/gpt-4o-mini
GCA_HOST=127.0.0.1
GCA_PORT=8000
GCA_ACCESS_TOKEN=
GCA_COMMAND_MODE=disabled
GCA_MAX_STEPS=20
GCA_MAX_TOTAL_STEPS=200
GCA_COMMAND_TIMEOUT=120
```

El token de acceso se exige automáticamente cuando el servidor escucha fuera de loopback. Todos los endpoints `/api/*`, incluido SSE, quedan protegidos cuando se configura.

## Controles y límites

- 20 pasos por tramo y 200 pasos totales por ejecución por defecto.
- Ciclos repetidos de herramientas detectados y detenidos.
- Archivos de hasta 2 MB; búsqueda de contenido de hasta 10 MB por operación.
- Archivado recuperable en `.gca/archive/`; las herramientas de archivos no hacen borrado permanente.
- Estado de conversación y caché local en `.gca/`, excluidos del paquete portable.

## Verificación

```powershell
.venv\Scripts\python.exe -m py_compile agent.py
```

## Licencia

PolyForm Noncommercial 1.0.0: uso personal y no comercial. Consulta [`LICENSE`](LICENSE) y los [términos oficiales](https://polyformproject.org/licenses/noncommercial/1.0.0).
