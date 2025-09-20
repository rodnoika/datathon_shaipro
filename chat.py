import os
import re
import json
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
load_dotenv()

import google.generativeai as genai

_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

def _iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _now_utc():
    return datetime.now(timezone.utc)

def parse_time_window(text: str):
    q = text.lower()
    now = _now_utc()
    if "последний час" in q or "за час" in q:
        return now - timedelta(hours=1), now
    if "за день" in q or "сегодня" in q:
        return now - timedelta(days=1), now
    if "последние 5 минут" in q or "за 5 минут" in q or "за пять минут" in q:
        return now - timedelta(minutes=5), now
    return now - timedelta(hours=1), now

def _extract_int(q: str, default: int) -> int:
    m = re.search(r"\b(\d{1,3})\b", q)
    if m:
        try:
            n = int(m.group(1))
            return max(1, min(1000, n))
        except:
            pass
    return default

def intent_to_query(query: str):
    q = query.lower()
    start, end = parse_time_window(q)
    event = None
    status = None

    if ("вход" in q or "логин" in q or "авторизац" in q):
        event = "auth"
    if ("неудач" in q or "ошиб" in q or "fail" in q):
        status = "fail"
    elif "успеш" in q:
        status = "success"

    op = "list"
    limit = 10
    if ("самый частый" in q or "топ" in q) and ("пользов" in q or "юзер" in q or "user" in q):
        op = "top_users"; limit = _extract_int(q, 5)
    elif ("самый частый" in q or "топ" in q) and ("ip" in q or "айпи" in q):
        op = "top_ips"; limit = _extract_int(q, 5)
    elif ("сколько" in q or "количеств" in q or "count" in q):
        op = "count"
    if op == "list" and ("атаки" in q or "подозрител" in q):
        op = "top_ips"; limit = _extract_int(q, 5)

    return {
        "start": start, "end": end,
        "event": event, "status": status,
        "op": op, "limit": limit
    }

def _coerce_datetime(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def intent_to_filter(query: str):
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY is not set")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(_GEMINI_MODEL)

    now = datetime.now(timezone.utc)

    system_rules = f"""
Ты помощник SecOps. Преобразуй русский запрос о логах в СТРОГИЙ JSON-фильтр.
ТЕКУЩЕЕ UTC ВРЕМЯ: "{_iso_utc(now)}"

Полям разрешены только значения:
- "start": ISO 8601 UTC, например "2025-09-20T13:05:00Z"
- "end":   ISO 8601 UTC
- "event": "auth" или null
- "status":"fail" или "success" или null

Правила интерпретации времени:
- "за час", "последний час"  → [now-1h, now]
- "за день", "сегодня"       → [now-24h, now]
- "за 5 минут", "последние 5 минут" → [now-5m, now]

Если речь о логинах и НЕУДАЧАХ → event="auth", status="fail".
Если неясно — ставь null.

Ответь ТОЛЬКО JSON-объектом без пояснений.
"""

    user_query = f'Запрос пользователя: """{query}"""'
    prompt = f"{system_rules.strip()}\n\n{user_query.strip()}\n\nВерни только JSON с ключами: start, end, event, status."

    resp = model.generate_content(prompt)
    text = (resp.text or "").strip()

    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        raise ValueError(f"Gemini did not return JSON: {text[:200]}...")

    parsed = json.loads(m.group(0))

    for key in ("start", "end", "event", "status"):
        if key not in parsed:
            raise ValueError(f"Missing key '{key}' in Gemini response")

    start_dt = _coerce_datetime(parsed["start"])
    end_dt   = _coerce_datetime(parsed["end"])

    event = parsed["event"]
    status = parsed["status"]

    if event not in (None, "auth"):
        raise ValueError(f"Invalid 'event': {event}")
    if status not in (None, "fail", "success"):
        raise ValueError(f"Invalid 'status': {status}")

    return {
        "start": start_dt,
        "end": end_dt,
        "event": event,
        "status": status
    }
