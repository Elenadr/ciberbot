#!/usr/bin/env python3
"""
CiberBot: resumen diario de noticias de ciberseguridad enviado a Telegram.

Flujo:
  1. Lee los feeds RSS de feeds.txt (+ catálogo KEV de CISA).
  2. Se queda con lo publicado en las últimas HOURS_BACK horas y que no se haya enviado antes.
  3. Pide a una IA (Groq gratis por defecto; también Ollama local o Claude) que agrupe
     duplicados, priorice y resuma en español.
  4. Envía el resumen a Telegram y guarda los enlaces enviados en seen.json.

Uso:
  python main.py              # ejecución normal
  python main.py --dry-run    # no envía a Telegram ni guarda estado; imprime el mensaje
  python main.py --check-feeds   # comprueba qué feeds responden
"""

import argparse
import html
import json
import logging
import os
import re
import sys
import time
from calendar import timegm
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import feedparser
import requests

BASE_DIR = Path(__file__).resolve().parent
FEEDS_FILE = BASE_DIR / "feeds.txt"
STATE_FILE = BASE_DIR / "seen.json"
ENV_FILE = BASE_DIR / ".env"

USER_AGENT = "Mozilla/5.0 (compatible; CiberBot/1.0; +https://github.com/)"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TELEGRAM_LIMIT = 4000  # Telegram admite 4096; dejamos margen

log = logging.getLogger("ciberbot")


# ---------------------------------------------------------------- configuración

def load_env(path: Path) -> None:
    """Carga un .env sencillo (CLAVE=valor) sin dependencias externas."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def cfg(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        sys.exit(f"Falta la variable {name} (ponla en .env)")
    return value or ""


def load_feeds() -> list[tuple[str, str]]:
    feeds = []
    for line in FEEDS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        name, url = (p.strip() for p in line.split("|", 1))
        feeds.append((name, url))
    return feeds


# ---------------------------------------------------------------- estado

def normalize_url(url: str) -> str:
    """Quita parámetros de tracking y fragmentos para deduplicar mejor."""
    parts = urlsplit(url.strip())
    query = "&".join(
        q for q in parts.query.split("&")
        if q and not q.lower().startswith(("utm_", "fbclid", "gclid"))
    )
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path.rstrip("/"), query, ""))


def load_state() -> dict[str, float]:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("seen.json corrupto; se empieza de cero")
    return {}


def save_state(state: dict[str, float], keep_days: int = 14) -> None:
    cutoff = time.time() - keep_days * 86400
    state = {k: v for k, v in state.items() if v >= cutoff}
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=0), encoding="utf-8")
    tmp.replace(STATE_FILE)


# ---------------------------------------------------------------- recogida

def clean_text(raw: str, limit: int = 400) -> str:
    text = re.sub(r"<[^>]+>", " ", raw or "")
    text = html.unescape(re.sub(r"\s+", " ", text)).strip()
    return text[:limit]


def entry_datetime(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        st = entry.get(key)
        if st:
            return datetime.fromtimestamp(timegm(st), tz=timezone.utc)
    return None


def fetch_feed(name: str, url: str) -> list[dict]:
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
    resp.raise_for_status()
    parsed = feedparser.parse(resp.content)
    if parsed.bozo and not parsed.entries:
        raise ValueError(f"feed ilegible: {parsed.bozo_exception}")
    items = []
    for e in parsed.entries:
        link = e.get("link")
        title = clean_text(e.get("title", ""), 200)
        if not link or not title:
            continue
        items.append({
            "source": name,
            "title": title,
            "link": link,
            "summary": clean_text(e.get("summary", "") or e.get("description", "")),
            "date": entry_datetime(e),
        })
    return items


def fetch_kev(since: datetime) -> list[dict]:
    resp = requests.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=25)
    resp.raise_for_status()
    items = []
    for v in resp.json().get("vulnerabilities", []):
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        # KEV solo da la fecha (sin hora): miramos el día completo
        if added < since.replace(hour=0, minute=0, second=0, microsecond=0):
            continue
        cve = v.get("cveID", "")
        items.append({
            "source": "CISA KEV",
            "title": f"{cve} – {v.get('vendorProject', '')} {v.get('product', '')}: "
                     f"{v.get('vulnerabilityName', '')}".strip(),
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "summary": clean_text(v.get("shortDescription", "")
                                  + (" Ransomware: sí." if v.get("knownRansomwareCampaignUse") == "Known" else "")),
            "date": added,
        })
    return items


def collect(hours_back: int, include_kev: bool) -> tuple[list[dict], list[str]]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    all_items, failed = [], []
    for name, url in load_feeds():
        try:
            items = fetch_feed(name, url)
            fresh = [i for i in items if i["date"] is None or i["date"] >= since]
            log.info("%-25s %3d entradas, %3d recientes", name, len(items), len(fresh))
            all_items.extend(fresh)
        except Exception as exc:  # un feed caído no debe tumbar el resto
            log.warning("%-25s ERROR: %s", name, exc)
            failed.append(name)
    if include_kev:
        try:
            kev = fetch_kev(since)
            log.info("%-25s %3d nuevas", "CISA KEV", len(kev))
            all_items.extend(kev)
        except Exception as exc:
            log.warning("CISA KEV ERROR: %s", exc)
            failed.append("CISA KEV")
    return all_items, failed


# ---------------------------------------------------------------- resumen con IA

SYSTEM_PROMPT = """Eres un analista de ciberseguridad que prepara un boletín diario MUY breve en español de España
para un profesional sin tiempo. Recibes una lista de noticias numeradas (id) de varias fuentes.

Tu tarea:
- Agrupa las noticias que hablan del mismo hecho (aunque vengan de fuentes distintas).
- Descarta lo irrelevante: publicidad, webinars, artículos patrocinados, opinión genérica, listas de "consejos".
- Clasifica cada hecho en una prioridad:
  "critico": vulnerabilidades explotadas activamente o 0-days, parches urgentes de productos muy usados, ataques en curso a gran escala.
  "alto": brechas de datos relevantes, ransomware contra organizaciones conocidas, campañas de malware/APT notables, incidentes en España.
  "medio": resto de noticias con interés (operaciones policiales, investigaciones, tendencias, regulación).
- Para cada hecho escribe UNA frase de máximo 25 palabras que diga qué ha pasado y a quién afecta. Sin relleno.
- Además escribe un "titular_del_dia": una frase que resuma lo más importante del día.

Responde SOLO con JSON válido, sin texto alrededor ni bloques de código, con este formato:
{"titular_del_dia": "...",
 "noticias": [{"prioridad": "critico|alto|medio", "resumen": "...", "ids": [3, 17]}]}

Ordena dentro de cada prioridad de más a menos importante. Máximo MAX_ITEMS hechos en total.
Usa solo ids que existan en la lista."""


# Proveedores con API compatible con OpenAI (Groq gratis, Ollama local gratis)
OPENAI_COMPATIBLE = {
    "groq": ("https://api.groq.com/openai/v1", "openai/gpt-oss-120b", "GROQ_API_KEY"),
    "ollama": ("http://localhost:11434/v1", "qwen3:8b", None),
}


def build_listing(items: list[dict], max_chars: int) -> tuple[str, list[dict]]:
    """Lista numerada para la IA, recortada para no pasar del límite de tokens."""
    lines, used = [], []
    total = 0
    for it in items:
        line = f"[{len(used)}] ({it['source']}) {it['title']} — {it['summary'][:150]}"
        if total + len(line) > max_chars:
            break
        lines.append(line)
        used.append(it)
        total += len(line) + 1
    return "\n".join(lines), used


def call_openai_compatible(base_url: str, api_key: str, model: str, system: str, user: str) -> str:
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    body = {
        "model": model,
        "temperature": 0.2,
        "max_tokens": 3000,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    if "gpt-oss" in model:
        body["reasoning_effort"] = "low"  # menos tokens de "pensamiento" → cabe en el plan gratis
    resp = requests.post(f"{base_url.rstrip('/')}/chat/completions", headers=headers, json=body, timeout=300)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"] or ""


def call_anthropic(api_key: str, model: str, system: str, user: str) -> str:
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json={"model": model, "max_tokens": 4000, "system": system,
              "messages": [{"role": "user", "content": user}]},
        timeout=180,
    )
    resp.raise_for_status()
    return "".join(b.get("text", "") for b in resp.json().get("content", []))


def summarize(items: list[dict], provider: str, max_items: int) -> tuple[dict, list[dict]]:
    """Devuelve (digest, items_usados). Los ids del digest apuntan a items_usados."""
    system = SYSTEM_PROMPT.replace("MAX_ITEMS", str(max_items))
    max_chars = int(cfg("AI_MAX_INPUT_CHARS", "14000" if provider == "groq" else "40000"))

    while True:
        listing, used = build_listing(items, max_chars)
        user = f"Noticias de hoy:\n\n{listing}"
        try:
            if provider == "anthropic":
                text = call_anthropic(cfg("ANTHROPIC_API_KEY", required=True),
                                      cfg("AI_MODEL", "claude-haiku-5-5"), system, user)
            else:
                base, default_model, key_var = OPENAI_COMPATIBLE[provider]
                text = call_openai_compatible(
                    cfg("AI_BASE_URL", base),
                    cfg(key_var, required=True) if key_var else "",
                    cfg("AI_MODEL", default_model), system, user)
            break
        except requests.HTTPError as exc:
            # 413/429 = demasiados tokens para el plan gratuito: reintentamos con menos noticias
            code = exc.response.status_code if exc.response is not None else 0
            if code in (413, 429) and max_chars > 4000:
                max_chars //= 2
                log.warning("La IA rechazó la petición (%s); reintento con menos noticias", code)
                time.sleep(20)
                continue
            raise

    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)  # algunos modelos locales "piensan" en voz alta
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise ValueError(f"La IA no devolvió JSON: {text[:300]}")
    return json.loads(match.group(0)), used


# ---------------------------------------------------------------- formato Telegram

PRIORITY_HEADERS = {
    "critico": "🔴 <b>Crítico</b>",
    "alto": "🟠 <b>Importante</b>",
    "medio": "🔵 <b>Otras noticias</b>",
}


def esc(text: str) -> str:
    return html.escape(text or "", quote=True)


def build_message(digest: dict, items: list[dict], failed: list[str]) -> str:
    today = datetime.now().strftime("%d/%m/%Y")
    lines = [f"🛡️ <b>Ciberseguridad · {today}</b>"]
    if digest.get("titular_del_dia"):
        lines.append(f"<i>{esc(digest['titular_del_dia'])}</i>")

    by_priority: dict[str, list[dict]] = {p: [] for p in PRIORITY_HEADERS}
    for n in digest.get("noticias", []):
        by_priority.setdefault(n.get("prioridad", "medio"), []).append(n)

    for prio, header in PRIORITY_HEADERS.items():
        news = by_priority.get(prio) or []
        if not news:
            continue
        lines.append("")
        lines.append(header)
        for n in news:
            links = []
            for idx in n.get("ids", []):
                if isinstance(idx, int) and 0 <= idx < len(items):
                    it = items[idx]
                    if it["link"] not in [l[1] for l in links]:
                        links.append((it["source"], it["link"]))
            link_txt = " · ".join(f'<a href="{esc(url)}">{esc(src)}</a>' for src, url in links[:3])
            lines.append(f"• {esc(n.get('resumen', ''))}" + (f" → {link_txt}" if link_txt else ""))

    if failed:
        lines.append("")
        lines.append(f"<i>⚠️ Sin respuesta hoy: {esc(', '.join(failed))}</i>")
    return "\n".join(lines)


def build_fallback(items: list[dict], failed: list[str], max_items: int, ai_failed: bool = True) -> str:
    """Sin IA (o si falla): titulares originales con enlace, lo más reciente primero."""
    today = datetime.now().strftime("%d/%m/%Y")
    lines = [f"🛡️ <b>Ciberseguridad · {today}</b>"]
    if ai_failed:
        lines.append("<i>(Resumen IA no disponible; titulares sin procesar)</i>")
    lines.append("")
    for it in items[:max_items]:
        lines.append(f'• <a href="{esc(it["link"])}">{esc(it["title"])}</a> ({esc(it["source"])})')
    if failed:
        lines.append(f"\n<i>⚠️ Sin respuesta hoy: {esc(', '.join(failed))}</i>")
    return "\n".join(lines)


def split_message(text: str, limit: int = TELEGRAM_LIMIT) -> list[str]:
    chunks, current = [], ""
    for line in text.split("\n"):
        if len(current) + len(line) + 1 > limit and current:
            chunks.append(current.rstrip("\n"))
            current = ""
        current += line + "\n"
    if current.strip():
        chunks.append(current.rstrip("\n"))
    return chunks


def send_telegram(token: str, chat_id: str, text: str) -> None:
    for chunk in split_message(text):
        for attempt in range(3):
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": chunk,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=30,
            )
            if r.ok:
                break
            log.warning("Telegram respondió %s: %s", r.status_code, r.text[:200])
            time.sleep(3 * (attempt + 1))
        else:
            raise RuntimeError("No se pudo enviar el mensaje a Telegram")
        time.sleep(1)


# ---------------------------------------------------------------- main

def check_feeds() -> None:
    for name, url in load_feeds():
        try:
            items = fetch_feed(name, url)
            print(f"OK    {name:25s} {len(items):3d} entradas")
        except Exception as exc:
            print(f"FALLO {name:25s} {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="imprime el mensaje sin enviarlo ni guardar estado")
    parser.add_argument("--check-feeds", action="store_true", help="comprueba que los feeds responden")
    args = parser.parse_args()

    load_env(ENV_FILE)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.check_feeds:
        check_feeds()
        return

    hours_back = int(cfg("HOURS_BACK", "24"))
    max_items = int(cfg("MAX_ITEMS", "15"))
    include_kev = cfg("INCLUDE_CISA_KEV", "true").lower() in ("1", "true", "yes", "si", "sí")
    provider = cfg("AI_PROVIDER", "groq").lower()
    if provider not in ("groq", "ollama", "anthropic", "none"):
        sys.exit(f"AI_PROVIDER desconocido: {provider} (usa groq, ollama, anthropic o none)")
    if not args.dry_run:
        token = cfg("TELEGRAM_BOT_TOKEN", required=True)
        chat_id = cfg("TELEGRAM_CHAT_ID", required=True)

    state = load_state()
    items, failed = collect(hours_back, include_kev)

    # Deduplicación: contra lo ya enviado y dentro de la tanda actual
    fresh, batch_seen = [], set()
    for it in items:
        key = normalize_url(it["link"])
        if key in state or key in batch_seen:
            continue
        batch_seen.add(key)
        fresh.append(it)
    # Lo más reciente primero; limitamos para controlar el coste
    fresh.sort(key=lambda i: i["date"] or datetime.now(timezone.utc), reverse=True)
    fresh = fresh[:150]
    log.info("Noticias nuevas a resumir: %d", len(fresh))

    if not fresh:
        message = f"🛡️ <b>Ciberseguridad · {datetime.now():%d/%m/%Y}</b>\nSin novedades relevantes en las últimas {hours_back} h."
    elif provider == "none":
        message = build_fallback(fresh, failed, max_items, ai_failed=False)
    else:
        try:
            digest, used = summarize(fresh, provider, max_items)
            message = build_message(digest, used, failed)
        except Exception as exc:
            log.error("Fallo al resumir con IA: %s", exc)
            message = build_fallback(fresh, failed, max_items)

    if args.dry_run:
        print("\n" + message)
        return

    send_telegram(token, chat_id, message)
    now = time.time()
    for it in fresh:
        state[normalize_url(it["link"])] = now
    save_state(state)
    log.info("Resumen enviado (%d caracteres)", len(message))


if __name__ == "__main__":
    main()
