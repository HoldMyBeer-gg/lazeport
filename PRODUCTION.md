# Production Deployment with Automatic HTTPS

This guide covers deploying Lazeport with **Caddy** for automatic HTTPS via Let's Encrypt.

**📌 If you're just developing locally, you don't need this!** Use `./run.sh` and HTTP. This guide is for deploying to a real server with a domain name.

---

## HTTPS Explained

**Why you can't test Let's Encrypt locally:**

- Let's Encrypt requires a **real domain name** (not localhost)
- Your domain must be **publicly accessible** from the internet
- Let's Encrypt servers need to verify you own the domain

**For local development:**

- Use HTTP (`http://localhost:8000`) - totally fine, no setup needed
- Optional: Use `mkcert` if you really need to test HTTPS locally (see below)

**For production:**

- Use a domain → Caddy gets real SSL certificates → automatic HTTPS

---

## Development vs Production

### Development

For local development with hot-reloading (no SSL):

```bash
./run_docker.sh            # builds the frontend, then starts the dev compose stack
./run_docker.sh --demo     # same, with sample data for the Trends page
./run_docker.sh --no-build # skip the frontend build (pair with `pnpm run build:watch`)
# or directly:
docker compose -f docker-compose.dev.yml up
```

Code changes:

- **Backend**: Auto-reloads (no rebuild)
- **Frontend**: Run `pnpm run build` in frontend folder - changes appear immediately

### Production

For production with automatic HTTPS:

```bash
docker compose up -d
```

---

## Option 1: Docker Compose (Recommended)

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server (e.g., `lazeport.yourdomain.com`)
- Ports 80 and 443 open in your firewall

### Setup

1. **Update Caddyfile.docker** - Replace `lazeport.pwn.zone` with your domain. The shipped file also strips the `Via` and `Server` headers, proxies everything to `app:8000`, and serves a static landing page from `./landing` at `/` (remove the two landing `handle` blocks if you don't ship one):

   ```caddyfile
   lazeport.yourdomain.com {
       encode gzip
       header -Via
       header -Server

       handle {
           reverse_proxy app:8000
       }

       log {
           output stdout
           format console
           level INFO
       }
   }
   ```

2. **Create `data/.env`** (Docker Compose passes this file to the `app` and `celery` containers; the app itself does not read `.env` files):

   ```bash
   mkdir -p data
   cp .env.example data/.env
   ```

   Edit `data/.env`:

   ```bash
   # Security (CHANGE THESE!)
   SESSION_SECRET_KEY=<generate-random-string-here>
   APP_SECRET_KEY=<generate-random-string-here>

   # Public URL, used for email links and the SSO callback
   PUBLIC_APP_URL=https://lazeport.yourdomain.com

   # Optional: outgoing email for invites and notifications
   #SMTP_HOST=smtp.example.com
   #SMTP_PORT=587
   #SMTP_USERNAME=...
   #SMTP_PASSWORD=...
   #SMTP_FROM=lazeport@example.com

   # Optional: only if users must reach Ollama/LM Studio or Jira on a private network
   #ALLOW_PRIVATE_LLM_URLS=1
   #ALLOW_PRIVATE_JIRA_URLS=1

   # Auth is enabled unless AUTH_DISABLED=1 is set. Never set it in production.

   # LLM providers, models and API keys are configured per user in the UI, not here.

   # Database: PostgreSQL is used by default. Credentials are in data/.postgres_password
   # (auto-created on first run, same pattern as data/.admin_password). No env vars needed.
   # For production, back up data/.postgres_password or the postgres_data Docker volume.
   ```

   Generate random secrets with:

   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

3. **Deploy**:

   ```bash
   docker compose up -d
   ```

4. **Get admin password**. It is printed once in the `app` container's startup banner and saved to `data/.admin_password` (owner-readable only):

   ```bash
   cat data/.admin_password
   # or
   docker compose logs app | grep -A 8 FIRST-RUN
   ```

5. **Access**: Visit `https://lazeport.yourdomain.com` - Caddy will automatically:
   - Obtain SSL certificate from Let's Encrypt
   - Renew certificates before expiry
   - Redirect HTTP → HTTPS

### Certificate Storage

Caddy stores certificates in the `caddy_data` Docker volume. They persist across restarts and are automatically renewed.

---

## Option 2: Native Installation with Caddy

### Prerequisites

- Linux/macOS server
- Python 3.12+ (CI tests 3.12 and 3.13; the container ships 3.13)
- Node.js 20.9+ and pnpm 10 (to build the frontend)
- Redis (broker for the background worker)
- Caddy installed
- Domain pointing to server

### Setup

1. **Install Caddy**:

   ```bash
   # macOS
   brew install caddy
   
   # Ubuntu/Debian
   sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   sudo apt update
   sudo apt install caddy
   ```

2. **Install app**:

   ```bash
   git clone <your-repo>
   cd lazeport
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cd frontend && pnpm install && pnpm run build && cd ..
   ```

3. **Configure Caddyfile** - Edit the production section:

   ```caddyfile
   lazeport.yourdomain.com {
       reverse_proxy localhost:8001
       encode gzip
       
       log {
           output file /var/log/caddy/lazeport.log
           format console
           level INFO
       }
   }
   ```

4. **Create the environment file** at `/opt/lazeport/data/.env` (the app does not load `.env` by itself, so systemd injects it). Start from `.env.example` and set at least `SESSION_SECRET_KEY`, `APP_SECRET_KEY`, `PUBLIC_APP_URL`, and, for PostgreSQL, `DATABASE_URL`; without `DATABASE_URL` the app uses SQLite at `data/lazeport.db`. `REDIS_URL` defaults to `redis://localhost:6379/0`.

5. **Create systemd services** for the backend (`/etc/systemd/system/lazeport.service`) and the background worker (`/etc/systemd/system/lazeport-worker.service`). Without the worker, AI generation and scanner imports stay queued forever.

   ```ini
   [Unit]
   Description=Lazeport Backend
   After=network.target redis.service

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/opt/lazeport
   EnvironmentFile=/opt/lazeport/data/.env
   Environment="PATH=/opt/lazeport/.venv/bin"
   ExecStart=/opt/lazeport/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8001 --no-server-header
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

   ```ini
   [Unit]
   Description=Lazeport Background Worker
   After=network.target redis.service

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/opt/lazeport
   EnvironmentFile=/opt/lazeport/data/.env
   Environment="PATH=/opt/lazeport/.venv/bin"
   ExecStart=/opt/lazeport/.venv/bin/celery -A app.celery_app worker --loglevel=info
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

6. **Start services**:

   ```bash
   # Start backend and worker
   sudo systemctl enable --now lazeport lazeport-worker

   # Start Caddy
   sudo systemctl enable caddy
   sudo systemctl restart caddy
   ```

7. **Get admin password**:

   ```bash
   sudo cat /opt/lazeport/data/.admin_password
   # or
   sudo journalctl -u lazeport | grep -A 8 FIRST-RUN
   ```

---

## Option 3: Local Development with Caddy

For testing SSL locally without Docker:

1. **Install Caddy** (see above)

2. **Run the helper script**:

   ```bash
   ./run_with_caddy.sh
   ```

   This starts:
   - FastAPI backend on port 8001
   - Caddy reverse proxy on port 8000

3. **Access**: `http://localhost:8000`

For local SSL testing, Caddy can use self-signed certificates, but browsers will show warnings.

---

## Security Headers

The app automatically adds these security headers via middleware:

✅ **Active:**

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` (comprehensive policy)
- `Permissions-Policy` (disables unused browser features)
- `Cache-Control` for sensitive API endpoints

✅ **When SSL is enabled:**

- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

The middleware automatically detects HTTPS (via `X-Forwarded-Proto` header from Caddy) and adds HSTS accordingly.

---

## Outbound URL Policy (SSRF Guard)

Users can point Lazeport at their own LLM endpoints and Jira instances, which means the server makes HTTP requests to user-chosen URLs. Before any such request, the URL must be `http` or `https`, carry no embedded credentials, and resolve only to public addresses. Loopback, RFC 1918, link-local (including cloud metadata at `169.254.169.254`), multicast, and reserved ranges are refused. The built-in Ollama default, `http://localhost:11434`, and the bundled provider presets are always allowed.

Two opt-in flags relax the address check for deployments that host these services on a private network:

| Variable | Effect |
|----------|--------|
| `ALLOW_PRIVATE_LLM_URLS=1` | Allow user-supplied LLM base URLs on private/loopback hosts (Ollama or LM Studio on a LAN). |
| `ALLOW_PRIVATE_JIRA_URLS=1` | Allow Jira connector URLs on private hosts (Jira Data Center behind the firewall). |

Leave both unset unless you need them. The check resolves DNS at validation time and does not defend against a hostname that changes its answer later (DNS rebinding); if that matters in your environment, pin the hostnames in `/etc/hosts` or keep the flags off.

Log lines are also scrubbed of newlines and control characters before they are written, so user-controlled values (emails, titles, model names) cannot forge log entries.

---

## Monitoring

### Check SSL status

```bash
curl -I https://lazeport.yourdomain.com
```

### View Caddy logs (Docker)

```bash
docker compose logs -f caddy
```

### View backend and worker logs (Docker)

```bash
docker compose logs -f app celery
```

### Check certificate expiry

```bash
echo | openssl s_client -connect lazeport.yourdomain.com:443 -servername lazeport.yourdomain.com 2>/dev/null \
  | openssl x509 -noout -dates
```

Certificates are automatically renewed at 2/3 of their lifetime (typically 60 days for Let's Encrypt's 90-day certs).

---

## Troubleshooting

### "Certificate not trusted" warning

- **Local dev**: Expected with self-signed certs. Click "Advanced" → "Proceed anyway"
- **Production**: Ensure your domain's DNS points to the server's IP

### Let's Encrypt rate limits

- Limit: 50 certificates per domain per week
- Use staging for testing: Add `acme_ca https://acme-staging-v02.api.letsencrypt.org/directory` to Caddyfile

### Port 80 required

Let's Encrypt needs port 80 for HTTP-01 challenge. Ensure:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### Check if ports are open

```bash
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443
```

---

## Production Checklist

- [ ] Domain DNS points to server
- [ ] Ports 80 and 443 open in firewall
- [ ] Updated Caddyfile with your domain
- [ ] Changed `SESSION_SECRET_KEY` and `APP_SECRET_KEY` in `data/.env`
- [ ] Set `PUBLIC_APP_URL` to your HTTPS URL (email links, SSO callback)
- [ ] `AUTH_DISABLED` is not set (authentication enabled)
- [ ] Backend running (Docker: `app` container; native: port 8001)
- [ ] Redis and the Celery worker running (AI generation and imports depend on them)
- [ ] Caddy running with updated config
- [ ] Tested HTTPS connection works
- [ ] Logged in once, changed the bootstrap admin password, and deleted or secured `data/.admin_password`
- [ ] Backed up `data/.postgres_password` and/or the `postgres_data` volume (PostgreSQL credentials)
- [ ] Set up regular database backups
- [ ] `ALLOW_PRIVATE_LLM_URLS` / `ALLOW_PRIVATE_JIRA_URLS` left unset unless you need LAN-hosted services

---

## Automatic Certificate Renewal

Caddy handles this automatically. No cron jobs needed. Certificates are renewed at 2/3 of their lifetime, so a 90-day Let's Encrypt cert renews at day 60.

Check that renewals are happening:

```bash
# Docker
docker compose logs caddy | grep -i "certificate obtained"

# Native
sudo journalctl -u caddy | grep -i "certificate obtained"
```

---

## Need Help?

- Caddy docs: https://caddyserver.com/docs/
- Let's Encrypt: https://letsencrypt.org/docs/
- FastAPI deployment: https://fastapi.tiangolo.com/deployment/
