import os
import time
import hashlib
import threading
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Set FRONTEND_ORIGIN to your deployed frontend URL, e.g. https://yourname.github.io
allowed_origin = os.getenv('FRONTEND_ORIGIN', '*').strip()
CORS(app, resources={r"/verify-turnstile": {"origins": allowed_origin}},
     methods=["POST", "OPTIONS"], allow_headers=["Content-Type"])

SECRET_KEY = os.getenv('TURNSTILE_SECRET_KEY', '').strip()
SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
# Extra best-effort replay guard for this running process. Cloudflare also makes
# Siteverify tokens single-use. For multi-instance deployments use a shared store.
_seen_tokens = {}
_seen_lock = threading.Lock()

@app.get('/')
def health():
    return jsonify({"ok": True, "service": "turnstile-verification"})

@app.post('/verify-turnstile')
def verify_turnstile():
    if not SECRET_KEY:
        return jsonify({"verified": False, "error": "server_not_configured"}), 500

    data = request.get_json(silent=True) or {}
    token = data.get('token')
    if not isinstance(token, str) or not token or len(token) > 4096:
        return jsonify({"verified": False, "one_time": False, "error": "missing_token"}), 400

    digest = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now = time.time()
    with _seen_lock:
        # Tokens expire quickly; prune old entries to keep memory bounded.
        for key, expiry in list(_seen_tokens.items()):
            if expiry < now:
                _seen_tokens.pop(key, None)
        if digest in _seen_tokens:
            return jsonify({"verified": False, "one_time": False, "error": "token_reused"}), 409
        # Reserve before contacting Cloudflare to prevent concurrent replay.
        _seen_tokens[digest] = now + 300

    try:
        response = requests.post(
            SITEVERIFY_URL,
            data={"secret": SECRET_KEY, "response": token,
                  "remoteip": request.headers.get('CF-Connecting-IP', request.remote_addr or '')},
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError):
        with _seen_lock:
            _seen_tokens.pop(digest, None)
        return jsonify({"verified": False, "one_time": False, "error": "cloudflare_unavailable"}), 502

    if result.get('success') is True:
        # Cloudflare tokens are single-use; only report success after Siteverify.
        return jsonify({"verified": True, "one_time": True}), 200

    with _seen_lock:
        _seen_tokens.pop(digest, None)
    return jsonify({"verified": False, "one_time": False, "error": "verification_failed"}), 400

if __name__ == '__main__':
    port = int(os.getenv('PORT', '10000'))
    app.run(host='0.0.0.0', port=port)
