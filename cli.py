"""
cli.py
------
Terminal interface for the Password Strength Analyzer.

Usage:
    python cli.py                  # interactive prompt, hidden input
    python cli.py "MyPassword123"  # analyze a single password directly
    python cli.py --report "MyPassword123"   # also write a PDF report
    python cli.py --generate                 # random 16-char password
    python cli.py --passphrase --words 6     # diceware-style passphrase

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
    gen = parser.add_argument_group("generator")
    gen.add_argument("--generate", action="store_true", help="Generate a random password and analyze it")
    gen.add_argument("--length", type=int, default=16, help="Password length (default 16)")
    gen.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    gen.add_argument("--no-digits", action="store_true", help="Exclude digits")
    gen.add_argument("--avoid-ambiguous", action="store_true", help="Exclude look-alike characters (Il1O0o...)")
    gen.add_argument("--passphrase", action="store_true", help="Generate a diceware-style passphrase and analyze it")
    gen.add_argument("--words", type=int, default=5, help="Passphrase word count (default 5)")
    gen.add_argument("--separator", default="-", help="Passphrase separator (default '-')")
    gen.add_argument("--capitalize", action="store_true", help="Capitalize passphrase words")
    gen.add_argument("--add-number", action="store_true", help="Append a random digit to the passphrase")
    args = parser.parse_args()

    if args.generate or args.passphrase:
        import generator
        try:
            if args.passphrase:
                out = generator.generate_passphrase(args.words, args.separator, args.capitalize, args.add_number)
            else:
                out = generator.generate_password(args.length, digits=not args.no_digits,
                                                  symbols=not args.no_symbols,
                                                  avoid_ambiguous=args.avoid_ambiguous)
        except ValueError as exc:
            print(f"  {exc}")
            sys.exit(2)
        print(f"\n  Generated {out['mode']}: {out['value']}")
        print(f"  Generator entropy: {out['generator_entropy_bits']} bits")
        result = analyze_password(out["value"])
        print_report(out["value"], result)
        if args.report:
            from report_generator import generate_report
            print(f"  Report written to {generate_report(out['value'], result, 'password_security_report.pdf')}\n")
        return

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
