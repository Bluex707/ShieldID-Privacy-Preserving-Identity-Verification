"""Security headers shared by all three Flask services."""
import secrets

from flask import g


def init_security_headers(app, no_store=True):
    """Adds a strict Content-Security-Policy (per-request script nonce), clickjacking,
    MIME-sniffing and referrer protections, and (optionally) no-store caching.

    Templates put ``nonce="{{ csp_nonce }}"`` on every inline <script>. Inline
    *styles* are still allowed ('unsafe-inline' for style-src only): style
    injection is far less dangerous than script injection and the templates use
    style attributes heavily.
    """

    @app.before_request
    def _make_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def _inject_nonce():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.after_request
    def _headers(resp):
        nonce = getattr(g, "csp_nonce", "")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if no_store and not resp.direct_passthrough and not resp.headers.get("Cache-Control"):
            if not getattr(resp, "is_streamed", False) and resp.mimetype in ("text/html", "application/json"):
                resp.headers["Cache-Control"] = "no-store"
        return resp
