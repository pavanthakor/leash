"""Thin synchronous client for local Ollama native tool-calling (/api/chat).

The agent loop hands the model a task plus a tool schema; Ollama returns an
assistant message that may contain `tool_calls`. This module does no policy and
no scripting -- it just relays messages to and from the model.
"""
import httpx

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL = "llama3.2:3b"


def chat(messages, tools, timeout=180):
    """One /api/chat turn. Returns the assistant `message` dict verbatim."""
    payload = {
        "model": MODEL,
        "messages": messages,
        "tools": tools,
        "stream": False,
        # temperature 0 for a repeatable demo -- the model still freely chooses
        # which tools to call; we only remove sampling noise.
        "options": {"temperature": 0},
    }
    r = httpx.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()["message"]


def ping():
    """True if Ollama answers and the model is present."""
    r = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=5)
    r.raise_for_status()
    names = [m.get("name") for m in r.json().get("models", [])]
    return MODEL in names
