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
SCAN_TYPE_MENU = (
    ("host", "Host and provider scan", "DNS, IP, TLS, technology, and RDAP provider"),
    ("subdomains", "Subdomain scan", "certificate logs plus bounded DNS resolution"),
    ("web", "Web vulnerability scan", "crawl and selected safe web checks"),
    ("ports", "Common-port exposure scan", "bounded TCP connect checks on common ports"),
    ("full", "Full authorized scan", "host, provider, subdomain, port, and web checks"),
)
SCAN_TYPES = tuple(item[0] for item in SCAN_TYPE_MENU)


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
    guided_parser.add_argument("--scan-type", choices=SCAN_TYPES)

    assess_parser = commands.add_parser(
        "assess", help="assess one authorized URL without creating a configuration"
    )
    assess_parser.add_argument("target", help="authorized website URL")
    assess_parser.add_argument("--output-dir", default="reports")
    assess_parser.add_argument("--scan-type", choices=SCAN_TYPES)
    assess_parser.add_argument(
        "--profile", choices=tuple(ASSESSMENT_PROFILES), help="skip the profile menu"
    )
    assess_parser.add_argument(
        "--allow-subdomains", action="store_true", help="allow crawling discovered subdomains"
    )

    scan_parser = commands.add_parser("scan", help="run an authorized assessment")
    scan_parser.add_argument("--config", default="aegisscope.json")
    scan_parser.add_argument("--output-dir", default="reports")
    scan_parser.add_argument("--scan-type", choices=SCAN_TYPES)
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


def choose_scan_type(choice: str) -> str:
    normalized = choice.strip().lower()
    if normalized.isdigit():
        index = int(normalized) - 1
        if 0 <= index < len(SCAN_TYPE_MENU):
            return SCAN_TYPE_MENU[index][0]
    if normalized in SCAN_TYPES:
        return normalized
    raise ValueError("choose a scan type from 1 to 5")


def configure_scan_type(config: ScanConfig, scan_type: str) -> None:
    config.reconnaissance = True
    config.provider_lookup = scan_type in {"host", "subdomains", "full"}
    config.passive_subdomains = scan_type in {"subdomains", "full"}
    config.resolve_subdomains = scan_type in {"subdomains", "full"}
    config.web_scan = scan_type in {"web", "full"}
    config.port_scan = scan_type in {"ports", "full"}


def prompt_scan_type() -> str:
    print("\nChoose the authorized scan type:")
    for index, (_, title, description) in enumerate(SCAN_TYPE_MENU, start=1):
        print(f"  {index}. {title}: {description}")
    return choose_scan_type(prompt_required("Selection [1-5]: "))


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
        f"Assessment complete: modules={','.join(result.modules)}, profile={profile}, "
        f"{result.stats.requests_sent} HTTP requests, "
        f"{len(result.findings)} findings ({confirmed} confirmed, {likely} likely)"
    )
    recon = result.reconnaissance
    if recon:
        addresses = recon.get("dns", {}).get("addresses", [])
        providers = [
            item.get("network_name") or "unknown"
            for item in recon.get("provider_records", [])
        ]
        technologies = [
            f"{item['name']} {item['version']}".strip()
            for item in recon.get("technologies", [])
        ]
        ct = recon.get("certificate_transparency", {})
        open_ports = recon.get("port_scan", {}).get("open_ports", [])
        print("\nDiscovered inventory:")
        print(f"  Host: {recon.get('hostname', 'unknown')}")
        print(f"  IP addresses: {', '.join(addresses) or 'none'}")
        print(f"  Provider: {', '.join(providers) or 'not selected/not available'}")
        print(f"  TLS: {recon.get('tls', {}).get('protocol', 'not observed')}")
        print(f"  Technologies: {', '.join(technologies) or 'none fingerprinted'}")
        print(f"  Observed headers: {len(recon.get('observed_headers', {}))}")
        print(f"  CT subdomains: {len(ct.get('subdomains', []))}")
        print(f"  Resolved subdomains: {len(recon.get('resolved_subdomains', []))}")
        print(
            "  Open common ports: "
            + (
                ", ".join(str(item["port"]) for item in open_ports)
                if open_ports
                else "none found/not selected"
            )
        )
    if "web" not in result.modules:
        print("\nWeb crawling was not selected. Choose scan type 3 or 5 for web vulnerability checks.")
    elif profile == "passive":
        print("\nPassive web checks ran. Choose injection, redirect, or full-safe for authorized input canaries.")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    print(f"Audit log: {audit_path}")
    return 0


def run_guided(
    config_path: str | Path,
    output_dir: str | Path,
    requested_scan_type: str | None = None,
) -> int:
    path = Path(config_path)
    print("AegisScope guided ethical web assessment")
    print("Use only on systems you own or have explicit written permission to test.\n")
    created = not path.exists()
    if not created:
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
    scan_type = requested_scan_type or prompt_scan_type()
    configure_scan_type(config, scan_type)
    if created:
        path.write_text(json.dumps(config.to_dict(), indent=2) + "\n", encoding="utf-8")
        print(f"Created {path}")

    profile = "passive"
    if config.web_scan:
        print("\nChoose the web assessment type:")
        for index, (_, title, description) in enumerate(PROFILE_MENU, start=1):
            print(f"  {index}. {title}: {description}")
        profile = choose_profile(prompt_required("Selection [1-4]: "))

    if ASSESSMENT_PROFILES[profile]:
        config.active_probes = True

    return execute_scan(config, output_dir, profile)


def run_url_assessment(args: argparse.Namespace) -> int:
    scan_type = args.scan_type or prompt_scan_type()
    profile = args.profile or "passive"
    if scan_type in {"web", "full"} and args.profile is None:
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
    configure_scan_type(config, scan_type)
    if ASSESSMENT_PROFILES[profile] and not config.web_scan:
        raise ValueError("active web profiles require scan type 'web' or 'full'")
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
                getattr(args, "scan_type", None),
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
        if args.scan_type:
            configure_scan_type(config, args.scan_type)
        if args.active and args.profile != "passive":
            raise ValueError("use either --active or --profile, not both")
        if ASSESSMENT_PROFILES[profile] and not args.confirm_authorization:
            raise ValueError("active profiles require --confirm-authorization")
        if ASSESSMENT_PROFILES[profile] and not config.active_probes:
            raise ValueError('set "active_probes": true in the reviewed configuration first')
        if ASSESSMENT_PROFILES[profile] and not config.web_scan:
            raise ValueError("active web profiles require scan type 'web' or 'full'")

        return execute_scan(config, args.output_dir, profile)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
