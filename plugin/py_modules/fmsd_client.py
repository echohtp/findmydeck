"""HTTP client for the identity-plane API — stdlib only (Decky-friendly)."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

# Decky's Python is compiled with OpenSSL default paths that don't exist on
# SteamOS, so create_default_context() ends up with an EMPTY trust store and
# every HTTPS call dies with "unable to get local issuer certificate".
# Load the OS bundle explicitly. Verification is never disabled.
_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",              # Arch/SteamOS, Debian
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",  # Arch alternative
    "/etc/ssl/cert.pem",                               # generic OpenSSL
    "/etc/pki/tls/certs/ca-bundle.crt",                # Fedora-likes
)

_ssl_ctx: ssl.SSLContext | None = None


def _ssl_context() -> ssl.SSLContext:
    global _ssl_ctx
    if _ssl_ctx is None:
        ctx = ssl.create_default_context()
        if ctx.cert_store_stats().get("x509_ca", 0) == 0:
            for path in _CA_BUNDLES:
                if os.path.exists(path):
                    try:
                        ctx.load_verify_locations(path)
                        break
                    except ssl.SSLError:
                        continue
        if ctx.cert_store_stats().get("x509_ca", 0) == 0:
            raise RuntimeError(
                "no CA bundle found on this system — cannot verify HTTPS")
        _ssl_ctx = ctx
    return _ssl_ctx


class ApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status = status


def _request(method: str, url: str, body: dict | None = None,
             token: str | None = None, timeout: int = 20):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as res:
            raw = res.read().decode()
            return res.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raise ApiError(e.code, e.read().decode(errors="replace")) from e


class Api:
    def __init__(self, server_url: str):
        self.base = server_url.rstrip("/")

    def enroll(self, pair_code: str, box_pk: str, sign_pk: str,
               salt: str, kdf: dict, device_name: str) -> dict:
        _, body = _request("POST", f"{self.base}/v1/enroll", {
            "pair_code": pair_code, "box_pk": box_pk, "sign_pk": sign_pk,
            "salt": salt, "kdf": kdf, "device_name": device_name,
        })
        return body

    def post_report(self, device_id: str, token: str, blob: str) -> bool:
        try:
            status, _ = _request("POST", f"{self.base}/v1/reports/{device_id}",
                                 {"blob": blob}, token=token)
            return status == 204
        except (ApiError, OSError):
            return False

    def get_command(self, device_id: str, token: str) -> dict | None:
        try:
            status, body = _request("GET", f"{self.base}/v1/command/{device_id}",
                                    token=token)
            return body if status == 200 else None
        except (ApiError, OSError):
            return None

    def get_ring(self, device_id: str, token: str) -> int:
        try:
            _, body = _request("GET", f"{self.base}/v1/ring/{device_id}", token=token)
            return int((body or {}).get("ring", 0))
        except (ApiError, OSError, ValueError):
            return 0

    def get_messages(self, device_id: str, token: str) -> list:
        try:
            _, body = _request("GET", f"{self.base}/v1/message/{device_id}", token=token)
            return (body or {}).get("messages", [])
        except (ApiError, OSError):
            return []

    def send_message(self, device_id: str, token: str, body: str) -> bool:
        try:
            status, _ = _request("POST", f"{self.base}/v1/message/{device_id}",
                                 {"body": body}, token=token)
            return status == 200
        except (ApiError, OSError):
            return False
