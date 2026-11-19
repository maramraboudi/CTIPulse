import argparse

from app.pipeline import collect
from app.reports import generate_report


def main() -> None:
    parser = argparse.ArgumentParser(description="CTI-Pulse CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser("collect", help="Collect and enrich CVEs")
    collect_parser.add_argument("cve_ids", nargs="*", help="Optional CVE identifiers")
    collect_parser.add_argument("--no-github", action="store_true", help="Skip GitHub PoC discovery")

    subparsers.add_parser("report", help="Generate the weekly intelligence report")

    args = parser.parse_args()
    if args.command == "collect":
        result = collect(args.cve_ids or None, github=not args.no_github)
        print(f"Collected {result['collected']} of {result['requested']} requested CVEs.")
    elif args.command == "report":
        path = generate_report()
        print(path)


if __name__ == "__main__":
    main()
