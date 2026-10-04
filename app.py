"""
app.py
------
Flask web application for the Password Strength Analyzer & Security
Awareness Tool.

Routes
------
GET  /              -> the single-page UI
POST /api/analyze   -> JSON {password} in, live analysis JSON out
POST /api/report     -> JSON {password} in, a downloadable PDF report out
POST /api/generate  -> JSON options in, generated password/passphrase + analysis out
GET  /api/wordlist  -> the (public) passphrase wordlist, for in-browser generation

Security notes
---------------
* This app is designed to run locally (localhost) for development/demo
  purposes, e.g. `python app.py`. It does not persist passwords anywhere:
  no database, no log line, no file write ever contains a raw password.
  Each request is analyzed in memory and discarded.
* If you were to deploy this publicly, the recommended next step would be
  to move the live-typing analysis entirely into client-side JavaScript so
  the password never leaves the browser at all (only the final "generate
  report" action would need a request, and even that could be done with a
  client-side PDF library instead). That tradeoff is called out here
  deliberately as part of the tool's own security-awareness message.
"""

from flask import Flask, render_template, request, jsonify, send_file
import io
import os
import tempfile

from analyzer import analyze_password, SECURITY_AWARENESS_TIPS
import generator

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def _resolve_live_breach_result(data: dict, password: str):
    """Two ways a caller can supply live-breach info:
    - {"hibp_result": {...}}   -- browser already checked HIBP directly
      (via Web Crypto + fetch, see templates/index.html) and is just
      passing the outcome along, e.g. so it can be baked into a PDF.
    - {"live_check": true}     -- ask THIS server to do the HIBP lookup
      itself (used by automated/non-browser callers). Not used by the
      bundled UI, which prefers to check directly from the browser."""
    if isinstance(data.get("hibp_result"), dict):
        r = data["hibp_result"]
        return {
            "checked": bool(r.get("checked")),
            "breached": bool(r.get("breached")),
            "count": int(r.get("count") or 0),
            "error": r.get("error"),
        }
    if data.get("live_check"):
        from hibp_checker import check_pwned_password
        return check_pwned_password(password)
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if len(password) > 256:
        return jsonify({"error": "Password too long."}), 400
    live_breach_result = _resolve_live_breach_result(data, password)
    result = analyze_password(password, live_breach_result=live_breach_result)
    return jsonify(result)


@app.route("/api/report", methods=["POST"])
def api_report():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided."}), 400
    if len(password) > 256:
        return jsonify({"error": "Password too long."}), 400

    from report_generator import generate_report
    live_breach_result = _resolve_live_breach_result(data, password)
    result = analyze_password(password, live_breach_result=live_breach_result)

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        generate_report(password, result, tmp_path)
        with open(tmp_path, "rb") as f:
            pdf_bytes = f.read()
    finally:
        os.remove(tmp_path)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="password_security_report.pdf",
    )


def _as_bool(value, default):
    return default if value is None else bool(value)


@app.route("/api/generate", methods=["POST"])
def api_generate():
    """Generate a random password or passphrase and analyze it.

    The result is generated server-side from the OS CSPRNG and returned
    once; nothing is stored or logged. (The bundled UI generates in the
    browser instead, so the secret never travels at all.)"""
    data = request.get_json(silent=True) or {}
    try:
        if data.get("mode", "password") == "passphrase":
            out = generator.generate_passphrase(
                words=int(data.get("words", 5)),
                separator=str(data.get("separator", "-")),
                capitalize=_as_bool(data.get("capitalize"), False),
                add_number=_as_bool(data.get("add_number"), False),
            )
        else:
            out = generator.generate_password(
                length=int(data.get("length", 16)),
                lowercase=_as_bool(data.get("lowercase"), True),
                uppercase=_as_bool(data.get("uppercase"), True),
                digits=_as_bool(data.get("digits"), True),
                symbols=_as_bool(data.get("symbols"), True),
                avoid_ambiguous=_as_bool(data.get("avoid_ambiguous"), False),
            )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    out["analysis"] = analyze_password(out["value"])
    return jsonify(out)


@app.route("/api/wordlist")
def api_wordlist():
    """Public, non-secret wordlist so the browser can build passphrases locally."""
    return jsonify({"words": generator.WORDLIST})


@app.route("/api/tips")
def api_tips():
    return jsonify({"tips": SECURITY_AWARENESS_TIPS})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
