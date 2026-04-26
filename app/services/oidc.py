"""
Generic OIDC (OpenID Connect) service for SSO.
Works with any OIDC-compliant provider: Okta, Google, Microsoft, Auth0, etc.
"""
from __future__ import annotations

import logging
import secrets

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from cryptography.fernet import InvalidToken

from app.db.adapter import StorageAdapter
from app.services.crypto import decrypt_text

log = logging.getLogger(__name__)

STATE_LENGTH = 32
SCOPES = "openid email profile phone"


def _extract_domain(email: str) -> str | None:
    """Extract domain from email, e.g. alice@acme.com -> acme.com."""
    if not email or "@" not in email:
        return None
    return email.strip().lower().split("@", 1)[1]


def _discovery_url(issuer: str) -> str:
    base = issuer.rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    return f"{base}/.well-known/openid-configuration"


async def _fetch_discovery(issuer: str) -> dict:
    """Fetch OIDC discovery document."""
    url = _discovery_url(issuer)
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


async def get_oidc_auth_url(
    adapter: StorageAdapter,
    org_id: str,
    provider_id: str,
    redirect_uri: str,
) -> tuple[str, str]:
    """
    Build authorization URL for OIDC flow.
    Returns (auth_url, state). Caller must store state in session.
    """
    config = adapter.get_org_oidc_config(org_id, provider_id)
    if not config:
        raise ValueError(f"OIDC provider {provider_id} not configured for org")

    try:
        client_secret = decrypt_text(config.client_secret_encrypted)
    except InvalidToken as e:
        log.exception("Failed to decrypt OIDC client secret for org %s (invalid/corrupt token): %s", org_id, e)
        raise ValueError("OIDC configuration is invalid")
    except (TypeError, ValueError) as e:
        log.exception("Failed to decrypt OIDC client secret for org %s: %s", org_id, e)
        raise ValueError("OIDC configuration is invalid")
    except Exception as e:
        log.exception("Failed to decrypt OIDC client secret for org %s: %s", org_id, e)
        raise ValueError("OIDC configuration is invalid")

    discovery = await _fetch_discovery(config.issuer)
    auth_endpoint = discovery["authorization_endpoint"]
    state = secrets.token_urlsafe(STATE_LENGTH)
    nonce = secrets.token_urlsafe(16)

    async with AsyncOAuth2Client(
        client_id=config.client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scope=SCOPES,
    ) as client:
        uri, _ = client.create_authorization_url(
            auth_endpoint,
            state=state,
            nonce=nonce,
        )
        return uri, state


async def exchange_code_for_userinfo(
    adapter: StorageAdapter,
    org_id: str,
    provider_id: str,
    redirect_uri: str,
    code: str,
    state: str,
    callback_url: str,
) -> dict:
    """
    Exchange authorization code for tokens and fetch user info.
    Returns dict with email, name, sub from OIDC claims.
    """
    config = adapter.get_org_oidc_config(org_id, provider_id)
    if not config:
        raise ValueError(f"OIDC provider {provider_id} not configured for org")

    try:
        client_secret = decrypt_text(config.client_secret_encrypted)
    except InvalidToken as e:
        log.exception("Failed to decrypt OIDC client secret for org %s (invalid/corrupt token): %s", org_id, e)
        raise ValueError("OIDC configuration is invalid")
    except (TypeError, ValueError) as e:
        log.exception("Failed to decrypt OIDC client secret for org %s: %s", org_id, e)
        raise ValueError("OIDC configuration is invalid")
    except Exception as e:
        log.exception("Failed to decrypt OIDC client secret for org %s: %s", org_id, e)
        raise ValueError("OIDC configuration is invalid")

    discovery = await _fetch_discovery(config.issuer)
    token_endpoint = discovery["token_endpoint"]
    userinfo_endpoint = discovery.get("userinfo_endpoint")

    async with AsyncOAuth2Client(
        client_id=config.client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        state=state,
    ) as client:
        token = await client.fetch_token(
            token_endpoint,
            authorization_response=callback_url,
        )
        if userinfo_endpoint:
            resp = await client.get(userinfo_endpoint)
            resp.raise_for_status()
            return dict(resp.json())
        # Fallback: use id_token claims if no userinfo endpoint
        id_token = token.get("id_token")
        if id_token:
            import base64
            import json
            parts = id_token.split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                return {
                    "sub": payload.get("sub"),
                    "email": payload.get("email"),
                    "name": payload.get("name") or payload.get("preferred_username", ""),
                }
        raise ValueError("No userinfo or id_token in OIDC response")
