"""
LLM-only lure reply engine (OpenAI-compatible API).

Configure in .env:
  REPLY_API_KEY=your_key
  REPLY_API_BASE_URL=https://api.groq.com/openai/v1
  REPLY_API_MODEL=llama-3.1-8b-instant
"""

from __future__ import annotations

import os
import re
from typing import Optional
from urllib.parse import urlparse

import requests

REPLY_API_KEY = os.getenv("REPLY_API_KEY") or os.getenv("OPENAI_API_KEY", "")
REPLY_API_BASE_URL = (
    os.getenv("REPLY_API_BASE_URL")
    or os.getenv("OPENAI_BASE_URL")
    or "https://api.openai.com/v1"
).rstrip("/")
REPLY_API_MODEL = os.getenv("REPLY_API_MODEL") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

LLM_TIMEOUT_SEC = float(os.getenv("REPLY_LLM_TIMEOUT_SEC", "12"))
REPLY_MAX_CHARS = int(os.getenv("REPLY_MAX_CHARS", "320"))

EMERGENCY_FALLBACK = "Sorry, I didn't catch that. Can you say that again?"

_history: dict[str, list[dict[str, str]]] = {}
MAX_HISTORY_TURNS = 6

BANNED_OUTPUT_PATTERNS = [
    r"\b(as an ai|language model|chatgpt|openai|groq)\b",
    r"\b(i am a bot|i'm a bot|system prompt|ignore previous)\b",
    r"https?://",
    r"\b(password|otp|api[_ ]?key|auth[_ ]?token)\b",
]

VICTIM_SYSTEM_PROMPT = """You are a normal person chatting on WhatsApp. You are polite and not very tech-savvy.
Rules:
- Write 1-2 short sentences only, plain English.
- Match what the other person said. Do not invent topics they did not mention.
- If they only say hi/hello, reply with a simple greeting only. Do NOT mention banks, SBI, YONO, KYC, or blocked accounts.
- Only discuss banking, KYC, apps, links, or installs if the other person already mentioned them.
- Never claim to be bank staff or police. Never share OTP, PIN, passwords, or real personal data.
- Never include URLs in your reply. Do not mention AI or bots.
"""

BRANCH_HINTS = {
    "greeting": (
        "They sent a short greeting (hi/hello). Reply with a brief friendly greeting only. "
        "Do not mention SBI, YONO, KYC, banks, or account problems."
    ),
    "kyc": "They mentioned KYC, blocked account, SBI, or YONO. Sound worried and ask what to do next.",
    "delay": "They asked you to click, update, install, or open something. Say you will try and ask for clear steps.",
    "thanks": "Acknowledge politely and ask them to stay online while you try.",
    "url": "You tried their link but it did not work. Ask for simpler steps or the file directly.",
    "media_pdf": "You received a PDF. Say you got it and ask what to do inside it.",
    "media_apk": "You received an app file. Say phone blocked it and ask how to install.",
    "media_other": "You received a file. Say you cannot open it and ask for simple steps.",
    "fallback": "Reply naturally to their message. Ask a short follow-up question if needed.",
}


def classify_branch(incoming_msg: str) -> str:
    msg = (incoming_msg or "").strip().lower()
    if not msg:
        return "greeting"
    if msg in ("hi", "hello", "hey", "hii", "hola", "start", "good morning", "good evening"):
        return "greeting"
    if "kyc" in msg or "blocked" in msg or "sbi" in msg or "yono" in msg:
        return "kyc"
    if any(k in msg for k in ("click", "update", "install", "link", "apk", "pdf")):
        return "delay"
    if any(k in msg for k in ("thank", "ok", "okay", "done", "received")):
        return "thanks"
    return "fallback"


def validate_reply(text: str) -> bool:
    if not text or not text.strip():
        return False
    cleaned = text.strip()
    if len(cleaned) > REPLY_MAX_CHARS:
        return False
    lowered = cleaned.lower()
    for pattern in BANNED_OUTPUT_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return False
    return True


def _trim_reply(text: str) -> str:
    cleaned = " ".join(text.strip().split())
    if len(cleaned) <= REPLY_MAX_CHARS:
        return cleaned
    return cleaned[: REPLY_MAX_CHARS - 3].rstrip() + "..."


def _history_add(sender_id: str, role: str, content: str) -> None:
    if not sender_id:
        return
    turns = _history.setdefault(sender_id, [])
    turns.append({"role": role, "content": content})
    if len(turns) > MAX_HISTORY_TURNS:
        _history[sender_id] = turns[-MAX_HISTORY_TURNS:]


def _llm_enabled() -> bool:
    return bool(REPLY_API_KEY)


def _build_user_prompt(incoming_msg: str, branch: str) -> str:
    hint = BRANCH_HINTS.get(branch, BRANCH_HINTS["fallback"])
    return f"Context: {hint}\nTheir message: {incoming_msg}\nYour reply:"


def _call_chat_api(messages: list[dict[str, str]]) -> Optional[str]:
    headers = {
        "Authorization": f"Bearer {REPLY_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": REPLY_API_MODEL,
        "messages": messages,
        "temperature": 0.6,
        "max_tokens": 120,
    }
    response = requests.post(
        f"{REPLY_API_BASE_URL}/chat/completions",
        headers=headers,
        json=payload,
        timeout=LLM_TIMEOUT_SEC,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"] or None


def generate_llm_reply(
    incoming_msg: str,
    branch: str,
    sender_id: str = "",
) -> Optional[str]:
    if not _llm_enabled():
        print("[REPLY] Set REPLY_API_KEY and REPLY_API_BASE_URL in .env")
        return None

    messages = [{"role": "system", "content": VICTIM_SYSTEM_PROMPT}]
    messages.extend(_history.get(sender_id, []))
    messages.append({"role": "user", "content": _build_user_prompt(incoming_msg, branch)})

    try:
        raw = _call_chat_api(messages)
        if not raw:
            return None

        trimmed = _trim_reply(raw)
        if validate_reply(trimmed):
            return trimmed

        print("[REPLY] LLM output failed validation.")
        return None
    except Exception as exc:
        print(f"[REPLY] LLM call failed: {exc}")
        return None


def get_lure_reply(
    incoming_msg: str,
    branch: Optional[str] = None,
    *,
    sender_id: str = "",
) -> str:
    resolved_branch = branch or classify_branch(incoming_msg)
    llm_text = generate_llm_reply(incoming_msg, resolved_branch, sender_id)

    if llm_text:
        print(f"[REPLY] LLM reply (branch={resolved_branch}).")
        _history_add(sender_id, "user", incoming_msg)
        _history_add(sender_id, "assistant", llm_text)
        return llm_text

    print("[REPLY] LLM unavailable, using emergency fallback.")
    return EMERGENCY_FALLBACK


def engine_status() -> str:
    llm = "on" if _llm_enabled() else "off"
    host = urlparse(REPLY_API_BASE_URL).netloc or REPLY_API_BASE_URL
    return f"llm_api endpoint={host} model={REPLY_API_MODEL} llm={llm}"
