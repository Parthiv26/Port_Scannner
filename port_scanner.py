#!/usr/bin/env python3
"""Simple TCP port scanner.

Use only on hosts and networks you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import errno
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urlparse


DEFAULT_PORTS = "1-1024"
CLOUD_WEBSITE_PORTS = "20,21,22,25,53,80,110,143,443,465,587,993,995,1433,1521,2049,2082,2083,2086,2087,3000,3306,3389,5000,5432,5601,5900,6379,8000,8080,8443,8888,9200,9300,11211,27017"


@dataclass(frozen=True)
class ScanResult:
    port: int
    status: str
    service: str | None = None
    detail: str | None = None

    @property
    def is_open(self) -> bool:
        return self.status == "open"


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated ports and ranges into a sorted unique list."""
    ports: set[int] = set()

    for part in value.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = parse_port_number(start_text)
            end = parse_port_number(end_text)
            if start > end:
                raise argparse.ArgumentTypeError(f"invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(parse_port_number(part))

    if not ports:
        raise argparse.ArgumentTypeError("at least one port is required")

    return sorted(ports)


def parse_port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port: {value}") from exc

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port out of range: {value}")
    return port


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise SystemExit(f"Could not resolve host {host!r}: {exc}") from exc


def normalize_target(target: str) -> str:
    """Accept hostnames, IPv4 addresses, and full website URLs."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    return host.strip()


def scan_port(host: str, port: int, timeout: float) -> ScanResult:
    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except socket.timeout:
            return ScanResult(
                port=port, status="filtered", service=service, detail="timeout"
            )
        except ConnectionRefusedError as exc:
            detail = errno.errorcode.get(exc.errno or 0, str(exc))
            return ScanResult(
                port=port, status="closed", service=service, detail=detail
            )
        except OSError as exc:
            result = getattr(exc, "winerror", None) or exc.errno or 0
            status = classify_socket_result(result)
            detail = errno.errorcode.get(result, str(exc))
            return ScanResult(
                port=port, status=status, service=service, detail=detail
            )

    return ScanResult(port=port, status="open", service=service)


def classify_socket_result(result: int) -> str:
    if result in {errno.ECONNREFUSED, 10061, 1225}:
        return "closed"
    if result in {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, 10060, 10065, 10051}:
        return "filtered"
    return "unreachable"


def scan_ports(host: str, ports: list[int], timeout: float, workers: int) -> list[ScanResult]:
    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port for port in ports
        }

        for future in as_completed(future_to_port):
            try:
                results.append(future.result())
            except OSError as exc:
                port = future_to_port[future]
                print(f"Skipping port {port}: {exc}", file=sys.stderr)

    return sorted(results, key=lambda item: item.port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan TCP ports on an authorized target."
    )
    parser.add_argument("host", help="Target website URL, hostname, or IPv4 address")
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=None,
        help="Ports to scan, for example: 22,80,443 or 1-1024",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds per port",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Number of concurrent scan workers",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Print closed, filtered, and unreachable ports as well as open ports",
    )
    parser.add_argument(
        "--cloud-website",
        action="store_true",
        help="Scan common website and cloud service ports",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.workers <= 0:
        parser.error("--workers must be greater than 0")

    target_host = normalize_target(args.host)
    ip_address = resolve_host(target_host)
    ports: list[int] = args.ports or parse_ports(
        CLOUD_WEBSITE_PORTS if args.cloud_website else DEFAULT_PORTS
    )

    scan_type = "cloud website" if args.cloud_website else "TCP"
    print(
        f"Scanning {scan_type} target {target_host} ({ip_address}) "
        f"across {len(ports)} port(s)..."
    )

    results = scan_ports(ip_address, ports, args.timeout, args.workers)
    open_results = [result for result in results if result.is_open]

    for result in results:
        if result.is_open:
            service = f" ({result.service})" if result.service else ""
            print(f"[OPEN]   {result.port}{service}")
        elif args.show_closed:
            service = f" ({result.service})" if result.service else ""
            detail = f" - {result.detail}" if result.detail else ""
            print(f"[{result.status.upper():7}] {result.port}{service}{detail}")

    print(f"\nScan complete: {len(open_results)} open port(s) found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
