"""
cli.py
------
Terminal interface for the Password Strength Analyzer.

Usage:
    python cli.py                  # interactive prompt, hidden input
    python cli.py "MyPassword123"  # analyze a single password directly
    python cli.py --report "MyPassword123"   # also write a PDF report

Uses the same analyzer.py used by the Flask web app, so results are
identical between the CLI and the browser UI.
"""

import argparse
import getpass
import sys

from analyzer import analyze_password


def _bar(score: int, width: int = 30) -> str:
    filled = round((score / 100) * width)
    return "#" * filled + "-" * (width - filled)


def print_report(password: str, result: dict) -> None:
    print()
    print(f"  Score:    {result['score']}/100  ({result['label']})")
    print(f"  [{_bar(result['score'])}]")
    print(f"  Length:   {result['length']} characters")
    print(f"  Entropy:  {result['entropy_bits']} bits")
    print()
    print("  Checklist:")
    labels = {
        "length_ok": "At least 8 characters",
        "length_strong": "At least 12 characters",
        "has_lowercase": "Has lowercase letters",
        "has_uppercase": "Has uppercase letters",
        "has_digits": "Has numbers",
        "has_symbols": "Has symbols",
        "not_common_password": "Not a known common password",
        "no_sequential_pattern": "No sequential characters",
        "no_repeated_pattern": "No repeated characters",
        "no_keyboard_walk": "No keyboard-walk pattern",
    }
    for key, text in labels.items():
        mark = "[x]" if result["checks"].get(key) else "[ ]"
        print(f"    {mark} {text}")
    print()
    print("  Estimated time to crack:")
    for scenario, t in result["crack_time_estimates"].items():
        print(f"    {scenario:<55} {t}")
    print()
    print("  Recommendations:")
    for rec in result["recommendations"]:
        print(f"    - {rec}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer (CLI)")
    parser.add_argument("password", nargs="?", help="Password to analyze (omit to be prompted, hidden input)")
    parser.add_argument("--report", action="store_true", help="Also write a PDF report to ./password_security_report.pdf")
    parser.add_argument("--live", action="store_true", help="Also check the password against the live Have I Been Pwned breach database (requires internet; only a 5-character hash prefix is ever sent)")
    args = parser.parse_args()

    password = args.password
    if password is None:
        try:
            password = getpass.getpass("Enter a password to analyze (input hidden): ")
        except Exception:
            password = input("Enter a password to analyze: ")

    if not password:
        print("No password entered.")
        sys.exit(1)

    live_breach_result = None
    if args.live:
        from hibp_checker import check_pwned_password
        print("  Checking against Have I Been Pwned (only a 5-char hash prefix is sent)...")
        live_breach_result = check_pwned_password(password)
        if live_breach_result.get("error"):
            print(f"  Couldn't reach Have I Been Pwned ({live_breach_result['error']}) -- continuing with local checks only.")

    result = analyze_password(password, live_breach_result=live_breach_result)
    print_report(password, result)

    if args.report:
        from report_generator import generate_report
        out_path = generate_report(password, result, "password_security_report.pdf")
        print(f"  Report written to {out_path}\n")


if __name__ == "__main__":
    main()
