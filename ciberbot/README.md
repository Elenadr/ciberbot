# CiberBot 🛡️

Resumen diario de noticias de ciberseguridad (incidentes, brechas, vulnerabilidades explotadas…) en Telegram, en español y con enlaces. **Coste: 0 €.**

Cada día:
1. lee los RSS de medios y organismos fiables (`feeds.txt`) y el catálogo KEV de CISA;
2. una IA gratuita (Groq) agrupa las noticias duplicadas, las prioriza y las resume;
3. te envía un único mensaje.

## 1. Crear el bot de Telegram (gratis)

1. En Telegram, habla con **@BotFather** → `/newbot` → elige nombre y usuario. Te da el **token**.
2. Abre un chat con tu bot nuevo y mándale cualquier mensaje (por ejemplo, `hola`).
3. Para obtener tu **chat id**, abre en el navegador:
   `https://api.telegram.org/bot<TU_TOKEN>/getUpdates`
   y busca `"chat":{"id": 123456789 ...}`.

## 2. Clave gratuita de Groq

Regístrate en <https://console.groq.com> → **API Keys** → *Create API Key*. El plan gratuito no pide tarjeta. Con una petición al día vas muy sobrado.

El bot ya recorta la lista de noticias para no pasar el límite de tokens por minuto del plan gratuito. Si aun así Groq rechaza la petición, reintenta con menos noticias.

### Otras opciones (`AI_PROVIDER` en `.env`)

| Valor | Coste | Notas |
|---|---|---|
| `groq` | Gratis | Por defecto. |
| `ollama` | Gratis | IA en tu propio ordenador ([ollama.com](https://ollama.com)), nada sale de tu red. Necesita un PC con 8–16 GB de RAM; en una Raspberry va demasiado lento. |
| `none` | Gratis | Sin IA: titulares originales con enlace, sin agrupar ni traducir. |
| `anthropic` | Céntimos al mes | Claude. Suele dar los mejores resúmenes. |

## 3. Dónde ejecutarlo (gratis)

### Opción A: cron en un equipo que tengas encendido (PC, Raspberry, NAS…)

```bash
git clone git@github.com:TU_USUARIO/ciberbot.git
cd ciberbot
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
cp .env.example .env && nano .env        # token, chat id y clave de Groq
chmod +x run.sh

./.venv/bin/python main.py --check-feeds  # ¿responden todos los feeds?
./.venv/bin/python main.py --dry-run      # muestra el mensaje sin enviarlo
./.venv/bin/python main.py                # envío real
```

Después, `crontab -e`:

```cron
CRON_TZ=Europe/Madrid
0 8 * * * /home/TU_USUARIO/ciberbot/run.sh >> /home/TU_USUARIO/ciberbot/bot.log 2>&1
```

`run.sh` hace un `git pull` antes de cada ejecución, así que los cambios que subas a GitHub se aplican solos.

### Opción B: sin ningún equipo encendido (GitHub Actions + cron-job.org)

GitHub ejecuta el bot gratis. Su programador interno a veces llega tarde, así que la hora exacta la marca **cron-job.org**, que también es gratis y se limita a darle al botón de *Run* a la hora fijada.

1. Sube el proyecto a GitHub (puede ser privado: el bot usa ~1 min al día, muy por debajo de los minutos gratuitos).
2. En el repo, ve a **Settings → Secrets and variables → Actions → New repository secret** y crea:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   - `GROQ_API_KEY`
3. Prueba que funciona en **Actions → ciberbot → Run workflow**.
4. Crea un token para que cron-job.org pueda lanzarlo:
   - Ve a GitHub → **Settings → Developer settings → Fine-grained tokens**.
   - Limítalo **solo a este repositorio**, con el permiso **Actions: Read and write**.
5. En <https://cron-job.org> crea un cronjob:
   - **URL:** `https://api.github.com/repos/TU_USUARIO/ciberbot/actions/workflows/ciberbot.yml/dispatches`
   - **Horario:** todos los días a las 08:00, zona horaria Europe/Madrid.
   - **Opciones avanzadas:**
     - método `POST`;
     - cabeceras `Authorization: Bearer TU_TOKEN`, `Accept: application/vnd.github+json` y `Content-Type: application/json`;
     - cuerpo `{"ref":"main"}`.

   Si responde **204**, está bien.

Las noticias ya enviadas se guardan en la caché de GitHub Actions entre un día y otro.

## Personalización

| Qué | Dónde |
|---|---|
| Añadir o quitar fuentes | `feeds.txt` (`Nombre \| URL`) |
| Número de noticias, ventana de horas, KEV | `.env` (o *Variables* en GitHub) |
| Criterios de prioridad, tono, longitud | `SYSTEM_PROMPT` en `main.py` |
| IA y modelo | `AI_PROVIDER`, `AI_MODEL` en `.env` |

## Detalles de funcionamiento

- **Sin repeticiones:** guarda los enlaces enviados en `seen.json` durante 14 días.
- **Tolerante a fallos:**
  - si un feed cae, el resto sigue y al final del mensaje se indica cuál falló;
  - si falla la IA, recibes igualmente los titulares con sus enlaces.
- **Enlaces fiables:** la IA solo devuelve los *ids* de las noticias y los enlaces los pone el script, así que no puede inventarse URLs.
- **Mensajes largos:** si el resumen supera el límite de Telegram, se trocea automáticamente.
