# NETH (នេត្រ) — The Digital Watchful Eye

An automated defensive gateway that protects the Khmer community from digital
financial fraud. NETH intercepts, parses, and classifies three threat vectors:

## Demo

<!-- Record your own per DEMO.md, save as demo/neth-demo.mp4, then it links here -->

▶️ **[Watch the demo](demo/neth-demo.mp4)** — scanning a scam QR, a phishing
message, and the Telegram bot. 

| # | Threat | Engine |
|---|--------|--------|
| 01 | KHQR payload tampering / identity-routing mismatch | `khqr_core` + `bakong_verify` |
| 02 | Physical QR sticker overlays on merchant placards | `vision_overlay` |
| 03 | Localized Khmer-language phishing / social engineering | `nlp_khmer` |

Every check returns one of three risk levels: **✅ Safe (0)**, **⚠️ Suspicious (1)**, **⛔ Blocked (2)**.

## Architecture

```
            ┌──────────────────────────────────────────────┐
            │  Front ends:  Web UI  ·  Telegram bot  ·  API │
            └───────────────────────┬──────────────────────┘
                                    │
                         ┌──────────▼──────────┐
                         │   scoring.NethGateway│  ← max-severity aggregation
                         └──────────┬──────────┘
         ┌──────────────┬──────────┼───────────┬───────────────┐
         ▼              ▼          ▼           ▼               ▼
   vision_overlay   khqr_core  bakong_verify  nlp_khmer    (your model)
   multi-QR /       TLV walker  account-id →  Khmer phishing
   extract          + CRC-16    holder name   heuristic/XLM-R
```

### Why identity, not checksum, is the core defense
A real overlay scam uses a **structurally perfect** KHQR pointing at the
attacker's own account — valid CRC, valid TLV. So `khqr_core` treats CRC/TLV as
a *validity pre-filter*, and the decisive check is `identity_match`: an
**offline cross-field check** comparing the displayed name (Tag 59) against the
account routing (Tag 29/30 bank code). If a QR labeled "ABA" routes to an
ACLEDA account, that's the classic overlay pattern → blocked.

> Note: the public Bakong API does **not** resolve an account id to a holder
> name (privacy/anti-enumeration), so identity defense is the cross-field
> routing check above — not a name lookup. `bakong_verify` is reserved for
> account-existence / transaction verification once a token is configured.

## Quick start

```bash
pip install -r requirements.txt        # core deps
uvicorn neth.api:app --reload          # then open http://127.0.0.1:8000/
pytest -q                              # run the offline smoke tests
```

The gateway is useful immediately with **no model download or API key** — the
NLP engine ships a working Khmer heuristic baseline, and KHQR/vision run offline.

## Telegram bot

### Use the bot (for everyone)
1. Open the bot in Telegram: **[@neth_watch_bot](https://t.me/neth_watch_bot)**
2. Press **Start**.
3. Send it either:
   - 📷 a **photo of a KHQR** to check it, or
   - 📝 a **forwarded message or link** you're unsure about.
4. It replies in Khmer with **✅ Safe / ⚠️ Suspicious / ⛔ Blocked** and the reason.

> Always confirm the recipient's name in your banking app before paying — NETH is
> an advisory aid, not a guarantee.

### Run your own bot

1. In Telegram, message **@BotFather** → `/newbot` → pick a name + username →
   copy the token it gives you.
2. Provide the token to NETH (any one of these — never commit it to git):
   - **File:** create `.telegram_token` in the project root containing just the token, or
   - **Env var:** `setx NETH_TELEGRAM_TOKEN "<token>"` (Windows; then open a new terminal), or
   - **Argument:** `python -m neth.bot <token>`
3. Install and run:
   ```bash
   pip install -r requirements.txt
   python -m neth.bot
   ```
   When you see `Telegram bot running…`, message your bot and press **Start**.

Notes:
- Only **one** instance may poll a token at a time — don't run it locally *and*
  on a server with the same token (Telegram returns a "Conflict" error).
- The token is a secret. `.telegram_token`, `.env`, and `*.token` are git-ignored.
- For always-on hosting (so the bot runs without your PC), see [DEPLOY.md](DEPLOY.md).

## Optional integrations (env vars)

| Variable | Enables |
|----------|---------|
| `NETH_BAKONG_TOKEN` | live Bakong account-name verification (the strong overlay defense) |
| `NETH_BAKONG_BASE`  | override Bakong API base URL |
| `NETH_NLP_MODEL`    | path to a fine-tuned XLM-RoBERTa Khmer classifier (else heuristic) |
| `NETH_URL_ONLINE`   | `1` to enable shortener expansion + URL threat feeds |
| `NETH_URLHAUS_KEY`  | URLhaus (abuse.ch) auth key for known-malicious-URL lookups |
| `NETH_GSB_KEY`      | Google Safe Browsing API key |
| `NETH_TELEGRAM_TOKEN` | run the Telegram bot: `python -m neth.bot` |

### URL reputation
`url_reputation.py` scores links in layers. **Offline (always on):** correct
canonical bank-domain matching (e.g. ABA = `ababank.com`, not `aba.com`),
brand-off-domain lookalikes, punycode/homoglyph hosts, IP-literal hosts, `@`
userinfo tricks, and shortener detection. **Online (opt-in via `NETH_URL_ONLINE=1`):**
shortener expansion plus URLhaus / Google Safe Browsing feeds — a feed hit is
decisive. Offline gives a usable prior; the feeds make accuracy *measurable*.

**Bank coverage.** The brand-lookalike list lives in
[`data/bank_domains.yaml`](data/bank_domains.yaml) (~30 Cambodian + international
brands) and is loaded at runtime — add a bank by editing YAML, no code change.
Brand-agnostic checks (feeds, IP/punycode/`@`/shortener/TLD) protect *every*
bank, listed or not; the lookalike rule only covers listed brands. ⚠️ A wrong
domain in the YAML flags the *real* bank — verify before adding.

## API

```
GET  /health
POST /api/analyze/text   {"text": "..."}        → verdict
POST /api/analyze/khqr   {"payload": "000201…"} → verdict
POST /api/analyze/image  multipart file=<photo> → verdict
POST /api/feedback       {input_type,input_excerpt,predicted_score,correct_label,note}
GET  /api/feedback/stats → counts + scam-missed-as-safe
```

Responses are **Khmer-first**: every verdict carries `summary_km` and each
signal a `reason_km`, with English kept alongside for logs. Inputs are size-
capped and the URL fetcher is SSRF-guarded (blocks internal/metadata IPs).

## Benchmarking accuracy

```bash
python scripts/fetch_eval_data.py --n 500   # download URLhaus + Tranco -> eval_data/
python bench_urls.py --phish eval_data/phish.txt --benign eval_data/benign.txt --sweep
python bench_gateway.py                      # whole-gateway: text + KHQR modalities
```

`bench_urls.py` measures the URL engine; `bench_gateway.py` measures the full
pipeline across text and KHQR. Bundled samples are tiny (validate logic, not a
real-world score) — use `fetch_eval_data.py` for a meaningful number.

## Feedback loop

Users can report wrong verdicts (web buttons / `POST /api/feedback`). Corrections
are stored in `data/feedback.db` (SQLite, git-ignored) as truncated excerpts —
not full payloads. Export for training with `FeedbackStore.export_jsonl()`. This
is how NETH gathers ground truth and the labeled corpus to train the Khmer NLP.

## Project layout

```
neth/
├── khqr_core.py      EMVCo/KHQR TLV parser + CRC-16 (validity pre-filter)
├── identity_match.py offline Tag 59 ↔ Tag 29/30 routing mismatch (overlay defense)
├── bakong_verify.py  account-existence / transaction verification (needs token)
├── nlp_khmer.py      Khmer phishing detector (heuristic + optional transformer)
├── url_reputation.py layered URL scoring (SSRF-guarded) + threat feeds
├── vision_overlay.py QR extraction + multi-QR overlay detection
├── scoring.py        signal aggregation → final verdict
├── i18n.py           Khmer localization of verdicts
├── feedback.py       SQLite feedback/ground-truth store
├── api.py            FastAPI server (JSON API + web UI)
├── bot.py            Telegram front end
└── web/              static UI (index.html, style.css, app.js)
bench_urls.py · bench_gateway.py · scripts/fetch_eval_data.py   benchmarking
data/bank_domains.yaml · data/bank_codes.yaml                   editable brand data
tests/test_engines.py                                           20 offline tests
```

## Limitations (read this)

NETH is an **advisory aid, not an authority.** It reduces risk on the *common*
scams; it does not guarantee a QR or link is safe. Always confirm the recipient
name in your banking app before paying. Known gaps:

- **Identity/routing check has limited coverage.** It only flags a name↔bank
  mismatch for banks whose codes are in [`data/bank_codes.yaml`](data/bank_codes.yaml)
  (currently 4: ABA, ACLEDA, Canadia, Wing). For any other bank it says *"couldn't
  verify routing"* — not *"safe."* It also **cannot** detect a scammer who pastes a
  QR for their own account at the *same* bank as the real merchant.
- **No account-name verification.** The public Bakong API does not expose
  account → holder-name lookup, so NETH cannot confirm *who* an account belongs
  to. Only your banking app can.
- **Khmer NLP is an unvalidated heuristic.** A keyword/URL model with **no measured
  accuracy**; it is evaded by rewording and will both miss scams and false-alarm.
  Treat its verdict as a weak hint until a model is trained on real labeled data.
- **Overlay (photo) detection is weak.** It flags *multiple* QR codes in a frame,
  but misses the common case where a sticker fully covers the original (one QR).
- **URL accuracy is unproven at scale.** The benchmark passes on a tiny bundled
  sample; no real-world precision/recall figure exists yet (see `bench_*`).
- **Threat feeds are opt-in and rate-limited.** Without `NETH_URL_ONLINE=1` and
  API keys, URL scoring is heuristic-only.
- **Not a substitute for vigilance.** A clever, well-localized scam with a valid
  QR and clean link can pass every check.

## Roadmap
- [ ] Train the XLM-RoBERTa Khmer phishing classifier on a labeled local dataset
- [ ] Train a YOLOv8 sticker-boundary model to augment `vision_overlay.detect()`
- [x] Known-bad URL/domain feed for `nlp_khmer` (URLhaus + Google Safe Browsing)
- [ ] Per-merchant known-good QR reference store for overlay comparison

> Open-source community edition. NETH assists detection; always verify the
> recipient name before paying.
