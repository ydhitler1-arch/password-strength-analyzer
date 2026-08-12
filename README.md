# CipherCheck — Password Strength Analyzer & Security Awareness Tool

Built for the Cyber Security Internship at Wyntrix Innovation OPC Private Limited.

A web app (with a CLI alternative) that analyzes password strength against
real-world attack patterns — not just "do you have a symbol" — and teaches
the person using it *why* a password is weak, not just that it is.

---

## Features

- **Live strength meter** — types the password once, see the score update instantly (client-side, no network round trip).
- **Complexity checklist** — length, character variety, and three pattern checks (sequential runs, repeated characters, keyboard walks).
- **Common-password / breach detection** — checked locally against a real 10,000-entry breached-password list (SecLists), with basic leetspeak normalization (`p@ssw0rd` → `password`) and trailing-digit stripping (`password123` → `password`). Optionally, click **"Check Have I Been Pwned"** to query the live HIBP database of 800M+ breached passwords via k-anonymity — only the first 5 characters of a SHA-1 hash are sent (computed in-browser via Web Crypto), so the password itself never leaves the device. Also available via `cli.py --live`.
- **Entropy & crack-time estimation** — bits of entropy plus estimated time to crack under four attack scenarios (throttled online, unthrottled online, offline slow hash, offline fast GPU hash).
- **Tailored recommendations** — specific, actionable fixes generated from what's actually missing in the password entered.
- **General security awareness tips** — always-visible, password-independent guidance (password managers, MFA, phishing, breach checking).
- **PDF report generation** — one-click downloadable report with the score, checklist, crack-time table, and recommendations. The password itself is masked in the report and never written to disk or logged anywhere.

## Project structure

```
password-strength-analyzer/
├── app.py                # Flask app: serves the UI + JSON/PDF API endpoints
├── analyzer.py            # Core analysis engine (entropy, checks, scoring, recommendations)
├── hibp_checker.py         # Live breach check against the HIBP Pwned Passwords API (k-anonymity)
├── report_generator.py    # Builds the PDF report from an analyzer.py result
├── cli.py                 # Terminal interface — same engine, no browser needed
├── requirements.txt
├── data/
│   └── common_passwords.txt   # 10,000-entry common/breached password list
└── templates/
    └── index.html          # Self-contained UI (inline CSS + JS, dark "security console" theme)
```

## Setup & running

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in a browser.

To use the CLI instead (no server needed):

```bash
python cli.py                       # interactive, hidden input
python cli.py "SomePassword123"     # analyze directly
python cli.py --report "SomePassword123"   # also writes a PDF report to the current folder
```

## How scoring works

`analyzer.py` computes two things and combines them:

1. **Entropy** — `length × log2(character pool size)`, where the pool size depends on which character categories (lowercase / uppercase / digits / symbols) are actually present. This is the standard brute-force estimate.
2. **Real-world weakness penalties** — entropy alone is misleading (`"password123"` has decent entropy by the formula above but is trivially guessable). So the score is capped hard if the password matches the common-password list, and penalized if it contains sequential runs, repeated characters, or keyboard walks.

The final 0–100 score maps to five labels: Very Weak, Weak, Fair, Strong, Very Strong.

## Live breach checking (Have I Been Pwned)

The local `data/common_passwords.txt` list only has 10,000 entries — useful
for instant, offline checks, but tiny next to real breach corpora. The
**"Check Have I Been Pwned"** button queries HIBP's Pwned Passwords API,
which covers 800M+ breached passwords, using the **k-anonymity** model
HIBP was specifically designed to support safely:

1. The browser computes the SHA-1 hash of the password locally (Web Crypto API).
2. Only the **first 5 hex characters** of that hash are sent to HIBP.
3. HIBP returns every hash suffix sharing that prefix (typically several hundred) along with breach counts.
4. The browser checks locally whether its own suffix is in that list.

The full password, and even its full hash, never leave the browser — HIBP
only ever sees a 5-character prefix shared by hundreds of unrelated
passwords. This is the same technique used by browser built-in breached-password
warnings. `hibp_checker.py` implements the equivalent check in Python for
`cli.py --live` and for non-browser callers of the Flask API.

This check requires internet access and is opt-in (button click), not run
automatically on every keystroke — both to respect the API and because a
network call on every keystroke would be poor practice for something this
sensitive, even with k-anonymity protecting it.

## Architecture note: why the logic exists in both Python and JavaScript

The live meter in the browser runs a JavaScript port of the same scoring
logic (`templates/index.html`) rather than calling the Flask API on every
keystroke. This was a deliberate choice, not duplication for its own sake:

- **Responsiveness** — instant feedback while typing, no debounce/network lag.
- **Security-by-architecture** — the password never has to leave the browser for the live meter to work. Only the final "Generate PDF Report" action sends it to the local Flask backend once, and even then it's never stored.
- **The client-side list is smaller** (300 common passwords, embedded inline) than the server-side list (10,000, loaded from `data/common_passwords.txt`), so the PDF report is the authoritative analysis — the live meter is a fast approximation of it.

If this were deployed as a public-facing product rather than a local demo
tool, the natural next step is to remove the password-transmission step
entirely — e.g. generate the PDF client-side too — so a password is never
sent over the network under any circumstance. That trade-off is written up
here on purpose: reasoning about where a password travels, even in your
own app, is itself part of the "security awareness" this project is
about.

## Privacy & security notes

- No database. No log line, error message, or file write anywhere in this codebase contains a raw password.
- Passwords are analyzed in memory per-request and discarded.
- The PDF report masks the password (`p********d`) rather than reproducing it.
- The bundled `common_passwords.txt` is a public breach-derived wordlist (via [SecLists](https://github.com/danielmiessler/SecLists)), used only for defensive matching — the same approach real tools like Have I Been Pwned and NIST's guidance recommend.

## Possible extensions

- Swap the local wordlist check for a live k-anonymity query against the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) for a much larger, continuously updated breach corpus.
- Add zxcvbn-style dictionary attack simulation (common words + l33t variants + name lists).
- Persist a score history (opt-in, no raw password stored) so a user can track improvement across their accounts over time.

## Review checklist mapping

| Requirement | Where it's implemented |
|---|---|
| Password Strength Analysis | `analyzer.py: analyze_password()` |
| Security Recommendations | `analyzer.py` recommendations block |
| Password Complexity Validation | `analyzer.py: _character_pools`, checklist |
| Common Password Detection | `analyzer.py: _matches_common_password`, `data/common_passwords.txt` |
| Security Awareness Tips | `analyzer.py: SECURITY_AWARENESS_TIPS`, awareness panel in UI |
| User-Friendly Interface | `templates/index.html` |
| Basic Report Generation | `report_generator.py`, `/api/report` |
