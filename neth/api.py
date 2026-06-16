#!/usr/bin/env python3
"""
NETH - FastAPI gateway.

Run:  uvicorn neth.api:app --reload
Then open http://127.0.0.1:8000/  for the web UI, or POST to the JSON API.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .feedback import FeedbackStore
from .scoring import NethGateway

# -- input limits (hardening) ------------------------------------------------
MAX_TEXT_LEN = 20_000       # forwarded messages are short; cap to avoid abuse
MAX_PAYLOAD_LEN = 2_000     # a KHQR string is a few hundred chars at most
MAX_IMAGE_BYTES = 8 * 1024 * 1024   # 8 MB upload ceiling
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/bmp", "image/heic"}

app = FastAPI(title="NETH Scam Detection Gateway", version="0.1.0")
gateway = NethGateway()
feedback = FeedbackStore()

WEB_DIR = Path(__file__).parent / "web"


class TextIn(BaseModel):
    text: str = Field(..., max_length=MAX_TEXT_LEN)


class KHQRIn(BaseModel):
    payload: str = Field(..., max_length=MAX_PAYLOAD_LEN)


class FeedbackIn(BaseModel):
    input_type: str = Field(..., max_length=16)
    input_excerpt: str = Field("", max_length=500)
    predicted_score: int = Field(..., ge=-1, le=2)
    correct_label: str = Field(..., max_length=16)   # safe | suspicious | scam
    note: str = Field("", max_length=500)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "neth", "version": "0.1.0"}


@app.post("/api/analyze/text")
def analyze_text(body: TextIn) -> dict:
    return gateway.analyze_text(body.text).as_dict()


@app.post("/api/analyze/khqr")
def analyze_khqr(body: KHQRIn) -> dict:
    return gateway.analyze_khqr(body.payload).as_dict()


@app.post("/api/analyze/image")
async def analyze_image(file: UploadFile = File(...)) -> dict:
    if file.content_type and file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(415, f"Unsupported image type: {file.content_type}")
    # Read with a hard ceiling so a huge upload can't exhaust memory.
    data = await file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(413, f"Image exceeds {MAX_IMAGE_BYTES // (1024 * 1024)} MB limit.")
    return gateway.analyze_image_bytes(data).as_dict()


@app.post("/api/feedback")
def submit_feedback(body: FeedbackIn) -> dict:
    fid = feedback.record(body.input_type, body.input_excerpt,
                          body.predicted_score, body.correct_label, body.note)
    return {"status": "recorded", "id": fid}


@app.get("/api/feedback/stats")
def feedback_stats() -> dict:
    return feedback.stats()


# -- serve the web UI --------------------------------------------------------
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(str(WEB_DIR / "index.html"))
