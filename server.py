import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlparse
from urllib.request import urlopen

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", 3000))
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
SESSION_SECRET = os.environ.get("NDDU_SESSION_SECRET", "")
COOKIE_SECURE = os.environ.get("NDDU_COOKIE_SECURE", "").lower() in ("1", "true", "yes")
APPROVED_EXTERNAL_EMAILS = {
    email.strip().lower()
    for email in os.environ.get("APPROVED_EXTERNAL_EMAILS", "").split(",")
    if email.strip()
}
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_authorized_email(email):
    normalized = email.strip().lower()
    domain = normalized.rsplit("@", 1)[-1]
    return domain == "nddu.edu.ph" or normalized in APPROVED_EXTERNAL_EMAILS


def create_session_token(email):
    payload = json.dumps({
        "authenticated": True,
        "email": email,
        "expires_at": int(time.time()) + 28800
    }, separators=(",", ":")).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256
    ).hexdigest()
    return f"{encoded_payload}.{signature}"


def read_session_token(token):
    try:
        encoded_payload, signature = token.split(".", 1)
        expected = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None

        padded_payload = encoded_payload + "=" * (-len(encoded_payload) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload).decode("utf-8"))
        if (
            not isinstance(payload, dict)
            or not payload.get("authenticated")
            or payload.get("expires_at", 0) <= time.time()
        ):
            return None
        return payload
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return None


class RepositoryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = os.path.normpath(unquote(parsed.path))
        if not path.startswith("/"):
            path = "/" + path

        if path in ("/", "/index.html", "/achievements.html") and not self.get_authenticated_user():
            self.send_response(302)
            self.send_header("Location", "/login.html")
            self.end_headers()
            return

        if path == "/api/me":
            self.handle_me()
            return

        if path == "/api/auth-config":
            self.send_json(200, {"clientId": GOOGLE_CLIENT_ID})
            return

        if path in ["/", ""]:
            path = "/index.html"

        if path.startswith("/api/"):
            self.send_json(404, {"success": False, "message": "Not found"})
            return

        file_path = os.path.abspath(os.path.join(ROOT_DIR, path.lstrip("/")))
        if os.path.commonpath((ROOT_DIR, file_path)) == ROOT_DIR and os.path.isfile(file_path):
            self.serve_file(file_path)
            return

        self.send_json(404, {"success": False, "message": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/google-login":
            self.handle_google_login()
            return

        if path == "/api/logout":
            self.handle_logout()
            return

        self.send_json(404, {"success": False, "message": "Not found"})

    def handle_google_login(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            self.send_json(400, {"success": False, "message": "Invalid request body"})
            return

        if not isinstance(data, dict):
            self.send_json(400, {"success": False, "message": "Invalid request body"})
            return

        credential = data.get("credential")
        credential = credential.strip() if isinstance(credential, str) else ""
        if not credential:
            self.send_json(400, {"success": False, "message": "Google credential is missing."})
            return
        if not GOOGLE_CLIENT_ID:
            self.send_json(503, {"success": False, "message": "Google sign-in is not configured."})
            return

        try:
            response = urlopen(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={quote(credential)}",
                timeout=5
            )
            payload = json.load(response)
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_json(401, {"success": False, "message": "Google sign-in could not be verified."})
            return

        if not isinstance(payload, dict):
            self.send_json(401, {"success": False, "message": "Google sign-in could not be verified."})
            return

        email_value = payload.get("email")
        email = email_value.strip() if isinstance(email_value, str) else ""
        email_verified = payload.get("email_verified") is True or payload.get("email_verified") == "true"
        issuer = payload.get("iss")
        try:
            token_not_expired = int(payload.get("exp", 0)) > time.time()
        except (TypeError, ValueError):
            token_not_expired = False

        if (
            not EMAIL_PATTERN.fullmatch(email)
            or not email_verified
            or payload.get("aud") != GOOGLE_CLIENT_ID
            or issuer not in ("accounts.google.com", "https://accounts.google.com")
            or not token_not_expired
        ):
            self.send_json(401, {"success": False, "message": "Google account is not verified."})
            return

        if not is_authorized_email(email):
            if "nddu" in email.lower():
                message = "An address containing “nddu” does not verify affiliation. Ask the repository administrator to approve your verified Google email."
            else:
                message = "This Google email is not approved. Ask the repository administrator to approve it."
            self.send_json(403, {"success": False, "message": message})
            return

        token = create_session_token(email.lower())
        cookie = cookies.SimpleCookie()
        cookie["auth"] = token
        cookie["auth"]["HttpOnly"] = True
        cookie["auth"]["SameSite"] = "Lax"
        cookie["auth"]["Max-Age"] = 28800
        cookie["auth"]["Path"] = "/"
        if COOKIE_SECURE:
            cookie["auth"]["Secure"] = True

        self.send_response(200)
        self.send_header("Set-Cookie", cookie.output(header=""))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": True, "message": "Login successful."}).encode("utf-8"))

    def handle_logout(self):
        self.send_response(200)
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_header("Set-Cookie", f"auth=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure}")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": True}).encode("utf-8"))

    def handle_me(self):
        payload = self.get_authenticated_user()
        if not payload:
            self.send_json(401, {"success": False})
            return

        self.send_json(200, {"success": True, "user": payload})

    def get_authenticated_user(self):
        cookie_header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(cookie_header)
        except cookies.CookieError:
            return None
        token = jar.get("auth")

        if not token:
            return None

        try:
            payload = read_session_token(token.value)
        except (ValueError, TypeError, AttributeError):
            payload = None
        return payload

    def serve_file(self, file_path):
        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".json": "application/json; charset=utf-8"
        }
        extension = os.path.splitext(file_path)[1].lower()
        mime_type = mime_types.get(extension, "application/octet-stream")

        with open(file_path, "rb") as handle:
            content = handle.read()

        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status_code, payload):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))


if __name__ == "__main__":
    if len(SESSION_SECRET.encode("utf-8")) < 32:
        print("NDDU_SESSION_SECRET must be set to at least 32 bytes.", file=sys.stderr)
        sys.exit(1)
    invalid_approved_emails = [
        email for email in APPROVED_EXTERNAL_EMAILS
        if not EMAIL_PATTERN.fullmatch(email)
    ]
    if invalid_approved_emails:
        print("APPROVED_EXTERNAL_EMAILS contains an invalid email address.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting server on http://localhost:{PORT}")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), RepositoryHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server")
        server.server_close()
