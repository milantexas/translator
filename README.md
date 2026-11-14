# Translator

Flask + vanilla JS. One container, two backends:
- `BACKEND=argos`: fully offline (Argos Translate). Free. Works on a Pi 4 or any server.
- `BACKEND=aws`: Amazon Translate. Fast, many languages, pay per character.

Edit `LANGS` (comma-separated codes) in `docker-compose.yml` to choose languages.

## Easiest: Portainer (point and click)
1. One time only, on the Pi, install Docker and Portainer (three copy-paste lines, see the chat instructions).
2. Put these files in a GitHub repository (website upload is fine; keep it public, there are no secrets in it).
3. In Portainer: Stacks, Add stack, Repository. Paste the repository URL, compose path `docker-compose.yml`.
4. Under Environment variables, add what you need, e.g. `APP_URL`, `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`. Leave the rest at their defaults.
5. Click Deploy the stack. The first build takes 10 to 20 minutes.

## Run locally (any machine)
    docker compose up --build
    open http://localhost:8000
First start downloads language models (a few hundred MB for 6 languages), then they're cached in a volume.

## Raspberry Pi 4
Use 64-bit Raspberry Pi OS and 4 GB+ RAM.
    curl -fsSL https://get.docker.com | sh && sudo usermod -aG docker $USER   # then log out/in
    scp -r translator pi@raspberrypi.local:~ && ssh pi@raspberrypi.local
    cd translator && docker compose up -d --build
Open http://raspberrypi.local:8000. Expect roughly 1-5 s per paragraph.
For access outside your home with HTTPS, use Tailscale or a Cloudflare Tunnel (no port forwarding).

## AWS
Option 1, offline model on a server: launch EC2 (t3.large, 20 GB disk, Amazon Linux or Ubuntu), install Docker, run the same compose file. Open port 8000 (or put Caddy/ALB in front for HTTPS).

Option 2, Amazon Translate (cheaper box, no models):
1. Create an IAM role with the `TranslateReadOnly` managed policy and attach it to the EC2 instance.
2. In `docker-compose.yml` set `BACKEND: aws`, `WITH_ARGOS: "0"`, `AWS_REGION: <your region>`.
3. `docker compose up -d --build` on a t3.micro or t3.small.

## Audio upload
Click **Upload audio** (or drop a file on the text box). The server transcribes it with Whisper (faster-whisper, runs on CPU), fills in the text and the detected language, then translates it.
- Formats: mp3, wav, m4a, ogg, webm, mp4. Limit 25 MB (`MAX_UPLOAD_MB`).
- `WHISPER_MODEL`: `tiny` is quickest on a Pi 4, `base` is the default, `small` is more accurate but slow on a Pi. On AWS use `small` on a t3.large or bigger.
- The Whisper model downloads on first upload, then is cached in the `/data` volume.
- If you pick a source language first, Whisper skips detection and is more accurate.

## Accounts, email and admin
Everything is stored in one SQLite file, `app.db`, in the Docker volume (`/data`): users (salted password hashes), preferences, and each user's last 200 translations.

**First run:** the first account you create becomes the admin and skips email confirmation, so you can't lock yourself out. Everyone after that must confirm their email before they can sign in.

**Email (SMTP).** Fill in the `SMTP_*` lines and `APP_URL` in `docker-compose.yml`, then `docker compose up -d`.
- Gmail: `SMTP_HOST: smtp.gmail.com`, port 587, `starttls`. Turn on 2-step verification, create an *App password*, and use it as `SMTP_PASSWORD`. `SMTP_USER` and `SMTP_FROM` are your Gmail address.
- Amazon SES: use the SMTP endpoint for your region (e.g. `email-smtp.us-east-1.amazonaws.com`), the SMTP credentials SES gives you, and a verified sender address.
- `APP_URL` must be the address your users open (with `http://` or `https://`). It's what goes in the email links, so use `localhost` only for testing.
- With `SMTP_HOST` empty, nothing is sent. The links are printed instead: `docker compose logs -f translator`. Good for testing.

**What users can do:** register with username, email and password; confirm by link (24 h); sign in with username or email; reset a forgotten password by link (1 h, single use). A reset signs the account out of every device. Users who signed up before email existed keep working and get a prompt to add one.

**Admin page** (`/admin`, linked in the header for admins):
- see every user, email status, last sign-in and saved-translation count
- turn public sign-ups on or off
- make or remove admins, disable or enable accounts (disabling signs them out right away)
- send a password-reset email, mark an email as confirmed, or delete a user and their history
- you can't demote, disable or delete yourself, so there is always an admin

**Other settings:** `COOKIE_SECURE: "1"` once you serve over HTTPS (leave "0" for plain http on your network, or login won't stick). Back up with `docker compose cp translator:/data/app.db ./app-backup.db`. Keep gunicorn at one worker (already set) so SQLite and the rate limits stay simple.

## HTTPS and access from outside your home
Pick one. Both avoid opening ports on your router, and both give you real HTTPS (needed for mic dictation and secure cookies).

**A. Tailscale Funnel (free, no domain needed).** Gives you `https://<pi-name>.<tailnet>.ts.net`.
    curl -fsSL https://tailscale.com/install.sh | sh
    sudo tailscale up
    sudo tailscale funnel --bg 8000
The first run prints a link to enable HTTPS certificates and Funnel in your Tailscale admin page. For private-only access (just your own devices) use `sudo tailscale serve --bg 8000` instead of `funnel`.

**B. Cloudflare Tunnel (free, needs a domain you own, about $10/yr).** In the Cloudflare Zero Trust dashboard create a tunnel, copy its token, then:
    docker run -d --restart unless-stopped --network host cloudflare/cloudflared:latest tunnel --no-autoupdate run --token <TOKEN>
Add a public hostname such as `translate.yourdomain.com` pointing to `http://localhost:8000`.

**Then update `docker-compose.yml` and run `docker compose up -d`:**
- `APP_URL: "https://<your https address>"` so email links point to it
- `COOKIE_SECURE: "1"`
- `TRUST_PROXY: "1"` so rate limits see each visitor's real IP instead of treating everyone as one
Once it's public: create your admin account first, then turn off sign-ups on the Admin page if you don't want strangers registering. Keep the Pi and containers updated.

## Notes
- Microphone dictation and speech need HTTPS (or localhost) and a supporting browser (Chrome/Safari).
- Login protects the app, but don't expose it to the open internet without HTTPS. Tailscale is the safest way to reach a Pi from outside your home.
