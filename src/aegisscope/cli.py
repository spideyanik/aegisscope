from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from . import __version__
from .authorization import require_owner_authorization, setup_owner_policy
from .branding import print_banner
from .config import ScanConfig, create_config, load_config
from .report import write_reports
from .scanner import ASSESSMENT_PROFILES, Scanner


PROFILE_MENU = (
    ("passive", "Passive audit", "headers, cookies, mixed content, and safe crawling"),
    ("injection", "Injection indicators", "input reflection and database error canaries"),
    ("redirect", "Redirect validation", "reserved-domain open redirect canary"),
    ("full-safe", "Full safe assessment", "all passive and non-destructive checks"),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisscope",
        description="Scope-enforced web security assessment CLI",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("owner-setup", help="configure the local owner authorization code")

    init_parser = commands.add_parser("init", help="create an assessment configuration")
    init_parser.add_argument("target", help="authorized target URL")
    init_parser.add_argument("--owner", required=True, help="person or organization granting access")
    init_parser.add_argument(
        "--authorization-reference",
        required=True,
        help="ticket, contract, program, or self-owned reference",
    )
    init_parser.add_argument(
        "--allow-subdomains", action="store_true", help="include subdomains of the target host"
    )
    init_parser.add_argument("--output", default="aegisscope.json", help="configuration path")

    validate_parser = commands.add_parser("validate", help="validate a configuration")
    validate_parser.add_argument("--config", default="aegisscope.json")

    guided_parser = commands.add_parser("guided", help="start the interactive assessment menu")
    guided_parser.add_argument("--config", default="aegisscope.json")
    guided_parser.add_argument("--output-dir", default="reports")

    assess_parser = commands.add_parser(
        "assess", help="assess one authorized URL without creating a configuration"
    )
    assess_parser.add_argument("target", help="authorized website URL")
    assess_parser.add_argument("--output-dir", default="reports")
    assess_parser.add_argument(
        "--profile", choices=tuple(ASSESSMENT_PROFILES), help="skip the profile menu"
    )
    assess_parser.add_argument(
        "--allow-subdomains", action="store_true", help="allow crawling discovered subdomains"
    )

    scan_parser = commands.add_parser("scan", help="run an authorized assessment")
    scan_parser.add_argument("--config", default="aegisscope.json")
    scan_parser.add_argument("--output-dir", default="reports")
    scan_parser.add_argument(
        "--profile",
        choices=tuple(ASSESSMENT_PROFILES),
        default="passive",
        help="assessment profile (default: passive)",
    )
    scan_parser.add_argument(
        "--active",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    scan_parser.add_argument(
        "--confirm-authorization",
        action="store_true",
        help="confirm you have current authorization for this target",
    )
    return parser


def choose_profile(choice: str) -> str:
    normalized = choice.strip().lower()
    if normalized.isdigit():
        index = int(normalized) - 1
        if 0 <= index < len(PROFILE_MENU):
            return PROFILE_MENU[index][0]
    if normalized in ASSESSMENT_PROFILES:
        return normalized
    raise ValueError("choose a profile from 1 to 4")


def prompt_required(label: str) -> str:
    try:
        value = input(label).strip()
    except EOFError as error:
        raise ValueError("interactive input ended unexpectedly") from error
    if not value:
        raise ValueError("a value is required")
    return value


def execute_scan(config: ScanConfig, output_dir: str | Path, profile: str) -> int:
    require_owner_authorization()
    destination = Path(output_dir)
    audit_path = destination / "audit.jsonl"
    with Scanner(config, audit_path, profile=profile) as scanner:
        result = scanner.run()
    json_path, markdown_path = write_reports(result, destination)
    confirmed = sum(finding.status == "confirmed" for finding in result.findings)
    likely = sum(finding.status == "likely" for finding in result.findings)
    print(
        f"Assessment complete: profile={profile}, {result.stats.requests_sent} requests, "
        f"{len(result.findings)} findings ({confirmed} confirmed, {likely} likely)"
    )
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    print(f"Audit log: {audit_path}")
    return 0


def run_guided(config_path: str | Path, output_dir: str | Path) -> int:
    path = Path(config_path)
    print("AegisScope guided ethical web assessment")
    print("Use only on systems you own or have explicit written permission to test.\n")
    if path.exists():
        config = load_config(path)
        print(f"Loaded target: {config.target}")
    else:
        target = prompt_required("Authorized target URL: ")
        owner = prompt_required("Authorization owner: ")
        reference = prompt_required("Authorization reference: ")
        try:
            subdomains = input("Include subdomains? [y/N]: ").strip().lower() == "y"
        except EOFError as error:
            raise ValueError("interactive input ended unexpectedly") from error
        config = create_config(target, owner, reference, subdomains)
        path.write_text(json.dumps(config.to_dict(), indent=2) + "\n", encoding="utf-8")
        print(f"Created {path}")

    print("\nChoose the web assessment type:")
    for index, (_, title, description) in enumerate(PROFILE_MENU, start=1):
        print(f"  {index}. {title}: {description}")
    profile = choose_profile(prompt_required("Selection [1-4]: "))

    if ASSESSMENT_PROFILES[profile]:
        config.active_probes = True

    return execute_scan(config, output_dir, profile)


def run_url_assessment(args: argparse.Namespace) -> int:
    profile = args.profile
    if profile is None:
        print("Choose the web assessment type:")
        for index, (_, title, description) in enumerate(PROFILE_MENU, start=1):
            print(f"  {index}. {title}: {description}")
        profile = choose_profile(prompt_required("Selection [1-4]: "))
    config = create_config(
        args.target,
        "Interactive Linux user",
        "interactive authorization confirmation",
        args.allow_subdomains,
    )
    config.active_probes = bool(ASSESSMENT_PROFILES[profile])
    return execute_scan(config, args.output_dir, profile)


def run(argv: list[str] | None = None) -> int:
    print_banner()
    if platform.system() != "Linux":
        print("error: AegisScope supports Linux systems only", file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    try:
        if args.command == "owner-setup":
            destination = setup_owner_policy()
            print(f"Owner authorization configured at {destination}")
            return 0

        if args.command in {None, "guided"}:
            return run_guided(
                getattr(args, "config", "aegisscope.json"),
                getattr(args, "output_dir", "reports"),
            )

        if args.command == "init":
            config = create_config(
                args.target,
                args.owner,
                args.authorization_reference,
                args.allow_subdomains,
            )
            output = Path(args.output)
            if output.exists():
                raise ValueError(f"refusing to overwrite existing file: {output}")
            output.write_text(json.dumps(config.to_dict(), indent=2) + "\n", encoding="utf-8")
            print(f"Created {output}")
            print("Passive scanning is enabled. Review the scope and limits before use.")
            return 0

        if args.command == "assess":
            return run_url_assessment(args)

        config = load_config(args.config)
        if args.command == "validate":
            print(f"Configuration is valid for {config.target}")
            return 0

        profile = "full-safe" if args.active else args.profile
        if args.active and args.profile != "passive":
            raise ValueError("use either --active or --profile, not both")
        if ASSESSMENT_PROFILES[profile] and not args.confirm_authorization:
            raise ValueError("active profiles require --confirm-authorization")
        if ASSESSMENT_PROFILES[profile] and not config.active_probes:
            raise ValueError('set "active_probes": true in the reviewed configuration first')

        return execute_scan(config, args.output_dir, profile)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
