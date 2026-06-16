#!/usr/bin/env python3
"""
NETH - Telegram bot front end (skeleton).

Set NETH_TELEGRAM_TOKEN and run:  python -m neth.bot
Users can forward a suspicious message, paste a KHQR string, or send a photo of
a QR placard; the gateway replies with a Safe / Suspicious / Blocked verdict.

Requires: pip install python-telegram-bot
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .scoring import GatewayVerdict, NethGateway

EMOJI = {0: "✅", 1: "⚠️", 2: "⛔"}

# Local secret file (git-ignored); an alternative to the env var.
TOKEN_FILE = Path(__file__).resolve().parent.parent / ".telegram_token"


def load_token() -> str | None:
    """Token from (1) NETH_TELEGRAM_TOKEN env var, (2) .telegram_token file,
    or (3) the first command-line argument. Never hard-code it in source."""
    tok = os.environ.get("NETH_TELEGRAM_TOKEN")
    if tok:
        return tok.strip()
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip()
    return None


def format_verdict(v: GatewayVerdict) -> str:
    # Khmer-first, with the engine name for transparency.
    lines = [f"{EMOJI[v.score]} *{v.summary_km or v.summary}*", ""]
    for s in v.signals:
        mark = EMOJI.get(max(s["score"], 0), "•")
        reason = s.get("reason_km") or s["reason"]
        lines.append(f"{mark} {reason}")
    lines.append("\n_សូមផ្ទៀងផ្ទាត់ឈ្មោះអ្នកទទួលក្នុងកម្មវិធីធនាគារ មុនពេលបង់ប្រាក់។_")
    return "\n".join(lines)


def main() -> None:
    token = load_token()
    if not token:
        raise SystemExit(
            "No token found. Provide it one of these ways:\n"
            "  • setx NETH_TELEGRAM_TOKEN \"<token>\"  (then open a NEW terminal)\n"
            "  • put the token in a file named .telegram_token in the project root\n"
            "  • python -m neth.bot <token>")

    from telegram import Update
    from telegram.constants import ParseMode
    from telegram.ext import (ApplicationBuilder, CommandHandler, ContextTypes,
                              MessageHandler, filters)

    gateway = NethGateway()

    WELCOME = (
        "👁️ *NETH (នេត) — ភ្នែកឃ្លាំមើលឌីជីថល*\n\n"
        "ផ្ញើមកខ្ញុំ៖\n"
        "• 📷 រូបថត KHQR ដើម្បីពិនិត្យការបោកប្រាស់\n"
        "• 📝 សារ ឬតំណ ដែលគួរសង្ស័យ\n\n"
        "ខ្ញុំនឹងប្រាប់ថា ✅ មានសុវត្ថិភាព / ⚠️ គួរប្រយ័ត្ន / ⛔ បានរារាំង។\n"
        "_សូមផ្ទៀងផ្ទាត់ឈ្មោះអ្នកទទួលក្នុងកម្មវិធីធនាគារជានិច្ច។_"
    )

    async def on_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await reply(update, WELCOME)

    async def reply(update: Update, text: str) -> None:
        # Try Markdown; if a stray character breaks it, send as plain text.
        try:
            await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:  # noqa: BLE001
            await update.message.reply_text(text)

    async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        text = update.message.text or ""
        # A pasted KHQR string starts with the EMVCo format indicator.
        if text.strip().startswith("000201"):
            verdict = gateway.analyze_khqr(text.strip())
        else:
            verdict = gateway.analyze_text(text)
        await reply(update, format_verdict(verdict))

    async def on_photo(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        photo = update.message.photo[-1]
        tg_file = await ctx.bot.get_file(photo.file_id)
        data = bytes(await tg_file.download_as_bytearray())
        verdict = gateway.analyze_image_bytes(data)
        await reply(update, format_verdict(verdict))

    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler(["start", "help"], on_start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_handler(MessageHandler(filters.PHOTO, on_photo))
    print("[neth] Telegram bot running…")
    app.run_polling()


if __name__ == "__main__":
    main()
