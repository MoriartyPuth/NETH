# NETH demo — recording guide

A real screen recording is the best demo. This is the shot list + exact inputs
so you can capture a clean ~90-second video. (Record with **Win+Alt+R** on
Windows, or OBS Studio.)

Save the final file as `demo/neth-demo.mp4` and it will show in the README.

## Setup (before recording)
```powershell
# terminal 1 — web app
uvicorn neth.api:app --reload
# terminal 2 — Telegram bot
python -m neth.bot
```
Open http://127.0.0.1:8000/ and your Telegram bot side by side.

## Shot list (~90s)

1. **Title (5s)** — show the web UI header: *NETH (នេត) — THE DIGITAL WATCHFUL EYE*.

2. **Scan a scam QR (20s)** — on the **📷 Scan QR Photo** tab, upload a photo of a
   QR whose name says one bank but routes to another. Show the verdict:
   **⛔ បានរារាំង — កុំបង់ប្រាក់** with the Khmer routing-mismatch reason.

3. **Scan a legit QR (15s)** — upload a normal personal/merchant QR →
   **✅ មានសុវត្ថិភាព**. Contrast with shot 2.

4. **Phishing text (20s)** — **📝 Text / URL** tab, paste:
   `Your ABA account suspended, verify http://aba-secure.xyz បន្ទាន់`
   → **⛔ បានរារាំង**, show the lookalike-URL reason.

5. **Telegram bot (20s)** — in Telegram, send the bot the same scam QR photo;
   show it replies with the identical Khmer verdict on the phone.

6. **Report button (10s)** — click a feedback button ("ពិតជាការបោកប្រាស់") to show
   the community-reporting loop.

## Sample inputs you can reuse
- Scam KHQR string (paste into the KHQR tab if you don't have a photo):
  `00020101021130350017kh.gov.nbc.bakong0110sokha@aclb53031165802KH5912ABA Merchant6010Phnom Penh63045FD2`
- Phishing text: `អ្នកបានឈ្នះរង្វាន់ពី ABA! ចុចលីង bit.ly/xx បន្ទាន់!`

## Tip
Keep it under 2 minutes, no audio needed — the Khmer verdicts tell the story.
