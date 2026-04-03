"""
ARGOS — AI Chat API
Freeform conversational endpoint backed by LM Studio (or rule fallback).
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()
log = logging.getLogger("argos.ai_chat")

_SYSTEM = (
    "You are ARGOS-AI, a cybersecurity expert assistant embedded in the ARGOS Security Platform. "
    "You help security analysts understand threats, interpret events, and make tactical decisions. "
    "Be concise, technical, and professional. Use precise cybersecurity terminology. "
    "Format code or commands in backticks. Keep replies under 300 words unless the question requires more detail."
)


class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []
    context: Optional[str] = None  # Optional: recent threat summary


@router.post("/chat")
async def ai_chat(req: ChatRequest, request: Request):
    ai = request.app.state.ai_engine

    if not ai._lmstudio_available:
        raise HTTPException(status_code=503, detail="AI backend not available — LM Studio not running")

    messages = [{"role": "system", "content": _SYSTEM}]

    if req.context:
        messages.append({
            "role": "user",
            "content": f"Current threat context from ARGOS:\n{req.context}"
        })
        messages.append({
            "role": "assistant",
            "content": "Understood. I have the current threat context. How can I assist you?"
        })

    for h in req.history[-10:]:  # last 10 turns max
        messages.append({"role": h.role, "content": h.content})

    messages.append({"role": "user", "content": req.message})

    model = ai._lmstudio_model or "local-model"
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            r = await client.post(
                f"{ai.lmstudio_url}/v1/chat/completions",
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": 0.3,
                    "max_tokens": 600,
                    "stream": False,
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            return {"reply": content.strip(), "model": model}
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="AI response timed out")
    except Exception as e:
        log.error(f"AI chat error: {e}")
        raise HTTPException(status_code=500, detail=f"AI error: {str(e)}")
