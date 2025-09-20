import os
import re
import json
from datetime import datetime, timedelta, timezone

def parse_time_window(text: str):
    text = text.lower()
    now = datetime.now(timezone.utc)
    if "последний час" in text or "за час" in text:
        return now - timedelta(hours=1), now
    if "за день" in text or "сегодня" in text:
        return now - timedelta(days=1), now
    if "последние 5 минут" in text or "за 5 минут" in text:
        return now - timedelta(minutes=5), now
    return now - timedelta(hours=1), now

def intent_to_filter_fallback(query: str):
    start, end = parse_time_window(query)
    filt = {"start": start, "end": end, "event": None, "status": None}
    q = query.lower()
    if ("вход" in q or "логин" in q) and "неудач" in q:
        filt["event"] = "auth"
        filt["status"] = "fail"
    elif "атаки" in q or "подозрительные" in q:
        filt["event"] = None
        filt["status"] = None
    return filt

_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

def _iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _coerce_datetime(s: str) -> datetime:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def intent_to_filter(query: str):
    """
    Преобразует натуральный запрос в фильтр:
    {
      "start": datetime,
      "end": datetime,
      "event": "auth" | null,
      "status": "fail" | "success" | null
    }
    Сначала пытается через Gemini, при ошибке — fallback.
    """
    try:
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            return intent_to_filter_fallback(query)

        import google.generativeai as genai  # pip install google-generativeai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(_GEMINI_MODEL)

        now = datetime.now(timezone.utc)
        # Жёстко задаём контракт ответа и контекст
        system_rules = f"""
Ты помощник SecOps. Твоя задача — преобразовать русский запрос пользователя о логах в строгий JSON-фильтр.
ТЕКУЩЕЕ UTC ВРЕМЯ: "{_iso_utc(now)}"
Полям разрешены только эти значения:
- "start": ISO 8601 UTC (например, "2025-09-20T13:05:00Z")
- "end": ISO 8601 UTC
- "event": "auth" или null
- "status": "fail" или "success" или null

Требования:
- Верни ТОЛЬКО JSON, без пояснений.
- Если во фразе "за час", "последний час" — это интервал [now-1h, now].
- Если "за день", "сегодня" — это [now-24h, now].
- Если "за 5 минут" — это [now-5m, now].
- Если событие про логины/входы и речь о неудачных входах — event="auth", status="fail".
- Если однозначно определить нельзя — ставь null.
"""

        user_query = f'Запрос пользователя: """{query}"""'

        prompt = f"{system_rules.strip()}\n\n{user_query.strip()}\n\nВерни только JSON с ключами: start, end, event, status."

        resp = model.generate_content(prompt)
        text = (resp.text or "").strip()

        m = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not m:
            return intent_to_filter_fallback(query)

        parsed = json.loads(m.group(0))

        start_s = parsed.get("start")
        end_s   = parsed.get("end")
        event   = parsed.get("event")
        status  = parsed.get("status")

        start_dt = _coerce_datetime(start_s) if isinstance(start_s, str) else datetime.now(timezone.utc) - timedelta(hours=1)
        end_dt   = _coerce_datetime(end_s) if isinstance(end_s, str) else datetime.now(timezone.utc)

        if event not in (None, "auth"):
            event = None
        if status not in (None, "fail", "success"):
            status = None

        return {
            "start": start_dt,
            "end": end_dt,
            "event": event,
            "status": status
        }

    except Exception:
        return intent_to_filter_fallback(query)
