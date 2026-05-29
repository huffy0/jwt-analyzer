import argparse
import json
from colorama import init, Fore, Style
from analyzer import analyze_jwt

init(autoreset=True)

def print_report(results):
    print("\n" + "="*55)
    print(Fore.CYAN + "         JWT SECURITY ANALYZER REPORT")
    print("="*55)

    print(Fore.YELLOW + "\n[HEADER]")
    for k, v in results["header"].items():
        print(f"  {k}: {v}")

    print(Fore.YELLOW + "\n[PAYLOAD]")
    for k, v in results["payload"].items():
        print(f"  {k}: {v}")

    print(Fore.YELLOW + "\n[SIGNATURE]")
    print(f"  {results['signature_status']}")

    print(Fore.YELLOW + "\n[SECURITY FINDINGS]")
    if not results["warnings"]:
        print(Fore.GREEN + "  No issues found.")
    for w in results["warnings"]:
        if w.startswith("CRITICAL"):
            print(Fore.RED + f"  ⚠  {w}")
        elif w.startswith("HIGH"):
            print(Fore.RED + f"  ✗  {w}")
        elif w.startswith("LOW"):
            print(Fore.YELLOW + f"  ⚡  {w}")
        else:
            print(Fore.GREEN + f"  ✓  {w}")

    print("\n" + "="*55 + "\n")

def main():
    parser = argparse.ArgumentParser(description="JWT Security Analyzer")
    parser.add_argument("token", help="The JWT token to analyze")
    parser.add_argument("--secret", help="Optional secret key to verify signature", default=None)
    args = parser.parse_args()

    try:
        results = analyze_jwt(args.token, args.secret)
        print_report(results)
    except ValueError as e:
        print(Fore.RED + f"Error: {e}")

if __name__ == "__main__":
    main()