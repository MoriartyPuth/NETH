# Deploying NETH

The container runs **both** the web app and the Telegram bot (the bot starts
automatically if `NETH_TELEGRAM_TOKEN` is set). It includes `libzbar0`,
`opencv-contrib-python-headless`, and the WeChat QR models so logo/stylized QR
codes (e.g. ABA Pay) decode in production.

## Option A — Railway (recommended if your GitHub is connected)

Railway auto-builds from the `Dockerfile` (see `railway.json`) and stays
always-on (no idle sleep). With GitHub connected, every push auto-deploys.

1. Railway dashboard → **New Project → Deploy from GitHub repo** → pick
   `MoriartyPuth/NETH`.
2. It detects the Dockerfile and builds automatically.
3. **Variables** tab → add `NETH_TELEGRAM_TOKEN` = your bot token (kept secret,
   never in git).
4. **Settings → Networking → Generate Domain** to expose the web UI; the bot
   starts automatically from `start.sh`.

> Railway is usage-based (~$5/mo hobby after the trial credit). The bot + web in
> one small service is cheap and always-on.

## Option B — Fly.io (easy, always-on bot)

> Fly is pay-as-you-go with a small allowance and needs a card on file. A
> 512 MB always-on machine is only a few dollars/month, often within allowance.

```bash
# 1. install the CLI  (https://fly.io/docs/flyctl/install/)
#    Windows PowerShell:
iwr https://fly.io/install.ps1 -useb | iex

# 2. log in
fly auth login

# 3. pick a unique app name (edit `app = ...` in fly.toml first), then launch
fly launch --no-deploy        # detects the Dockerfile; keep existing fly.toml

# 4. add your bot token as a SECRET (not in git, not in the image)
fly secrets set NETH_TELEGRAM_TOKEN=123456:ABC...your-new-token

# 5. deploy
fly deploy
```

Your web UI: `https://<app-name>.fly.dev/` · the bot goes live the moment the
machine boots. `min_machines_running = 1` keeps it always on for the bot.

## Option C — truly free, always-on VPS (Oracle Cloud / GCP free tier)

Best if you want **zero cost** forever. Provision an always-free small VM
(Oracle Cloud Always-Free ARM, or GCP e2-micro), install Docker, then:

```bash
git clone <your-repo> neth && cd neth
docker build -t neth .
docker run -d --restart unless-stopped -p 80:8080 \
  -e NETH_TELEGRAM_TOKEN=123456:ABC...your-token \
  --name neth neth
```

`--restart unless-stopped` keeps the bot alive across reboots/crashes.

## Option D — Render

Works, but the **free** web service **sleeps after ~15 min idle**, which delays
bot replies. Use a paid "Background Worker" for an always-on bot, or prefer A/B.

## Notes
- **Secrets:** the bot token is supplied as a host env var/secret. The local
  `.telegram_token` file is git- and docker-ignored, so it never ships.
- **Feedback DB** (`data/feedback.db`) is ephemeral on these hosts — it resets on
  redeploy. For durable feedback, mount a volume or use a hosted DB.
- **Bakong API** returns HTTP 403 outside Cambodia; it stays token-gated/off, so
  this does not affect the web/bot demo.
- **Region:** `sin` (Singapore) is the closest Fly region to Cambodia for low
  latency.
