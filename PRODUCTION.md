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
docker-compose -f docker-compose.dev.yml up
```

Code changes:

- **Backend**: Auto-reloads (no rebuild)
- **Frontend**: Run `pnpm run build` in frontend folder - changes appear immediately

### Production

For production with automatic HTTPS:

```bash
docker-compose up -d
```

---

## Option 1: Docker Compose (Recommended)

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server (e.g., `lazeport.yourdomain.com`)
- Ports 80 and 443 open in your firewall

### Setup

1. **Update Caddyfile.docker** - Replace the domain:

   ```caddyfile
   lazeport.yourdomain.com {
       reverse_proxy app:8000
       encode gzip
       
       log {
           output stdout
           format console
           level INFO
       }
   }
   ```

2. **Create production .env**:

   ```bash
   cp .env .env.production
   ```

   Edit `.env.production`:

   ```bash
   # LLM Provider
   LLM_PROVIDER=ollama  # or openai
   OPENAI_API_KEY=sk-...  # if using OpenAI
   
   # Security (CHANGE THESE!)
   SESSION_SECRET_KEY=<generate-random-string-here>
   APP_SECRET_KEY=<generate-random-string-here>
   
   # Auth (enabled in production)
   # AUTH_DISABLED=0  # or just remove this line
   
   # Database: PostgreSQL is used by default. Credentials are in data/.postgres_password
   # (auto-created on first run, same pattern as data/.admin_password). No env vars needed.
   # For production, back up data/.postgres_password or the postgres_data Docker volume.
   ```

   Generate random secrets with:

   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **Deploy**:

   ```bash
   docker-compose up -d
   ```

4. **Get admin password**:

   ```bash
   docker-compose logs app | grep ADMIN_PASSWORD
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
- Python 3.10+
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

4. **Create systemd service** for the backend (`/etc/systemd/system/lazeport.service`):

   ```ini
   [Unit]
   Description=Lazeport Backend
   After=network.target
   
   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/opt/lazeport
   Environment="PATH=/opt/lazeport/.venv/bin"
   ExecStart=/opt/lazeport/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8001
   Restart=always
   
   [Install]
   WantedBy=multi-user.target
   ```

5. **Start services**:

   ```bash
   # Start backend
   sudo systemctl enable lazeport
   sudo systemctl start lazeport
   
   # Start Caddy
   sudo systemctl enable caddy
   sudo systemctl restart caddy
   ```

6. **Get admin password**:

   ```bash
   sudo journalctl -u lazeport | grep ADMIN_PASSWORD
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

## Monitoring

### Check SSL status

```bash
curl -I https://lazeport.yourdomain.com
```

### View Caddy logs (Docker)

```bash
docker-compose logs -f caddy
```

### View backend logs (Docker)

```bash
docker-compose logs -f app
```

### Check certificate expiry

Caddy shows certificate info in logs. Certificates are automatically renewed at 2/3 of their lifetime (typically 60 days for Let's Encrypt's 90-day certs).

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
- [ ] Changed `SESSION_SECRET_KEY` and `APP_SECRET_KEY` in `.env`
- [ ] Set `AUTH_DISABLED=0` or remove it (enable authentication)
- [ ] Backend running on port 8001
- [ ] Caddy running with updated config
- [ ] Tested HTTPS connection works
- [ ] Saved bootstrap admin password securely (`data/.admin_password`)
- [ ] Backed up `data/.postgres_password` and/or the `postgres_data` volume (PostgreSQL credentials)
- [ ] Set up regular database backups

---

## Automatic Certificate Renewal

Caddy handles this automatically. No cron jobs needed. Certificates are renewed at 2/3 of their lifetime, so a 90-day Let's Encrypt cert renews at day 60.

Check renewal status:

```bash
# Docker
docker-compose exec caddy caddy list-modules

# Native
caddy list-modules
```

---

## Need Help?

- Caddy docs: https://caddyserver.com/docs/
- Let's Encrypt: https://letsencrypt.org/docs/
- FastAPI deployment: https://fastapi.tiangolo.com/deployment/
