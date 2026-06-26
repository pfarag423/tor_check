#!/usr/bin/env python3
"""Check whether an IPv4 *or* IPv6 address is a Tor exit node, and emit firewall
block syntax for a chosen vendor.

Requires: pip install dnspython   (only needed for the IPv4 path)

Detection by address family
----------------------------
IPv4: Tor DNS Exit List, ip-port service. Answers the precise question
      "Is EXIT_IP a Tor exit relay allowed to exit to DEST_IP:PORT?"; a match
      resolves to 127.0.0.2. Query format:
          <reversed-exit-ip>.<port>.<reversed-dest-ip>.ip-port.exitlist.torproject.org

IPv6: The DNSEL has no IPv6 zone, so we use the Onionoo details API
      (onionoo.torproject.org, no key required). We treat EXIT_IP as a Tor exit
      if it is an address of a running relay carrying the "Exit" flag. This is
      relay-level (not per dest:port), which is the best the public data offers
      for IPv6.
"""

import argparse
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

EXITLIST_ZONE = "ip-port.exitlist.torproject.org"
MATCH_ANSWER = "127.0.0.2"  # the A record the DNSEL returns on a positive hit
ONIONOO_URL = "https://onionoo.torproject.org/details"


# --------------------------------------------------------------------------- #
# IPv4 detection -- Tor DNSEL (ip-port)
# --------------------------------------------------------------------------- #
def reverse_ip(ip: str) -> str:
    """1.2.3.4 -> 4.3.2.1 (octet order reversed, as the DNSEL expects)."""
    return ".".join(reversed(str(ipaddress.IPv4Address(ip)).split(".")))


def _dnsel_lookup(exit_ip: str, dest_ip: str, port: int) -> bool:
    """True if exit_ip is a Tor exit permitting exit to dest_ip:port (IPv4)."""
    try:
        import dns.resolver
        import dns.exception
    except ImportError as exc:
        raise RuntimeError(
            "dnspython is required for the --dest-ip DNSEL check "
            "(pip install -r requirements.txt). Omit --dest-ip to use the "
            "Onionoo relay-level check instead.") from exc

    query = f"{reverse_ip(exit_ip)}.{port}.{reverse_ip(dest_ip)}.{EXITLIST_ZONE}"
    try:
        answers = dns.resolver.resolve(query, "A")
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.DNSException as exc:
        raise RuntimeError(f"DNS request failed for {query}: {exc}") from exc
    return any(str(rdata) == MATCH_ANSWER for rdata in answers)


# --------------------------------------------------------------------------- #
# IPv6 detection -- Onionoo details API
# --------------------------------------------------------------------------- #
def _strip_port(addr: str) -> str:
    """'[2001:db8::1]:443' -> '2001:db8::1' ; '1.2.3.4:443' -> '1.2.3.4'."""
    if addr.startswith("["):
        return addr[1:addr.index("]")]
    return addr.rsplit(":", 1)[0]


def _relay_addresses(relay: dict):
    for a in relay.get("or_addresses", []):
        yield _strip_port(a)
    yield from relay.get("exit_addresses", [])


def _onionoo_lookup(exit_ip: str, timeout: int = 15) -> bool:
    """True if exit_ip belongs to a running relay flagged 'Exit' (v4 or v6)."""
    target = ipaddress.ip_address(exit_ip)
    url = f"{ONIONOO_URL}?" + urllib.parse.urlencode(
        {"type": "relay", "running": "true", "search": str(target)})
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"Onionoo request failed: {exc}") from exc

    for relay in data.get("relays", []):
        if "Exit" not in relay.get("flags", []):
            continue
        for addr in _relay_addresses(relay):
            try:
                if ipaddress.ip_address(addr) == target:
                    return True
            except ValueError:
                continue
    return False


def uses_dnsel(exit_ip: str, dest_ip: str | None) -> bool:
    """The precise per-dest:port DNSEL check applies only to IPv4 when a
    destination IP is supplied; otherwise we fall back to relay-level Onionoo."""
    return dest_ip is not None and ipaddress.ip_address(exit_ip).version == 4


def is_tor_exit(exit_ip: str, dest_ip: str | None, port: int) -> bool:
    """Use the precise IPv4 DNSEL check when --dest-ip is given, otherwise the
    relay-level Onionoo check (works for both IPv4 and IPv6)."""
    if uses_dnsel(exit_ip, dest_ip):
        return _dnsel_lookup(exit_ip, dest_ip, port)
    return _onionoo_lookup(exit_ip)


# --------------------------------------------------------------------------- #
# Firewall rule generators (IPv4 + IPv6)
#
# Every generator blocks the IP in BOTH directions and is written to be
# idempotent: it reuses deterministic, IP-derived object/rule names and a shared
# structure so re-applying the same output does not create duplicate entries.
# --------------------------------------------------------------------------- #
def _label(ip: str) -> str:
    """Identifier-safe label: 1.2.3.4 -> TOR-1-2-3-4 ; 2001:db8::1 -> TOR-2001-db8--1."""
    return "TOR-" + ip.replace(".", "-").replace(":", "-")


def _host_cidr(ip: str) -> str:
    return f"{ip}/32" if ipaddress.ip_address(ip).version == 4 else f"{ip}/128"


def _cisco_ios(ip: str) -> str:
    if ipaddress.ip_address(ip).version == 4:
        return f"""! Cisco IOS - block TOR exit node {ip} (both directions, IPv4)
! Re-applying identical ACEs to a named ACL does not duplicate them.
ip access-list extended BLOCK-TOR
 remark Block TOR {ip}
 deny ip host {ip} any
 deny ip any host {ip}"""
    return f"""! Cisco IOS - block TOR exit node {ip} (both directions, IPv6)
ipv6 access-list BLOCK-TOR-V6
 remark Block TOR {ip}
 deny ipv6 host {ip} any
 deny ipv6 any host {ip}"""


def _cisco_asa(ip: str) -> str:
    obj = _label(ip)
    v6note = "" if ipaddress.ip_address(ip).version == 4 else \
        "\n! Unified ACL syntax; requires ASA 9.0+ for IPv6 objects."
    return f"""! Cisco ASA - block TOR exit node {ip} (both directions){v6note}
object network {obj}
 host {ip}
access-list BLOCK-TOR extended deny ip object {obj} any
access-list BLOCK-TOR extended deny ip any object {obj}"""


def _checkpoint(ip: str) -> str:
    obj = _label(ip)
    addr_param = "ip-address" if ipaddress.ip_address(ip).version == 4 else "ipv6-address"
    return f"""# Check Point - block TOR exit node {ip} (both directions)
# Unique object/rule names make re-runs error rather than duplicate.
mgmt_cli add host name "{obj}" {addr_param} "{ip}"
mgmt_cli add access-rule layer "Network" position 1 \\
    name "Block {obj} (in)"  source "{obj}"      action "Drop"
mgmt_cli add access-rule layer "Network" position 1 \\
    name "Block {obj} (out)" destination "{obj}" action "Drop"
mgmt_cli publish"""


def _ubiquiti(ip: str) -> str:
    if ipaddress.ip_address(ip).version == 4:
        grp, group_kw, name_kw = "TOR-BLOCK", "address-group", "name"
        chain_in, chain_out = "WAN_IN", "WAN_OUT"
    else:
        grp, group_kw, name_kw = "TOR-BLOCK-V6", "ipv6-address-group", "ipv6-name"
        chain_in, chain_out = "WANv6_IN", "WANv6_OUT"
    return f"""# Ubiquiti EdgeOS - block TOR exit node {ip} (both directions)
# Members accumulate in a shared group; adding a dup address is a no-op.
configure
set firewall group {group_kw} {grp} address {ip}
set firewall {name_kw} {chain_in}  rule 100 action drop
set firewall {name_kw} {chain_in}  rule 100 description 'Block TOR (inbound)'
set firewall {name_kw} {chain_in}  rule 100 source group {group_kw} {grp}
set firewall {name_kw} {chain_out} rule 100 action drop
set firewall {name_kw} {chain_out} rule 100 description 'Block TOR (outbound)'
set firewall {name_kw} {chain_out} rule 100 destination group {group_kw} {grp}
commit
save
exit"""


def _firewalld(ip: str) -> str:
    fam = "ipv4" if ipaddress.ip_address(ip).version == 4 else "ipv6"
    return f"""# firewalld - block TOR exit node {ip} (both directions)
# Rich rules are idempotent: re-adding an identical rule is a no-op warning.
firewall-cmd --permanent --add-rich-rule='rule family="{fam}" source address="{ip}" drop'
firewall-cmd --permanent --add-rich-rule='rule family="{fam}" destination address="{ip}" drop'
firewall-cmd --reload"""


def _fortinet(ip: str) -> str:
    obj = _label(ip)
    if ipaddress.ip_address(ip).version == 4:
        addr_block = f"""config firewall address
    edit "{obj}"
        set subnet {ip}/32
    next
end"""
        policy_kw, src_kw, dst_kw = "policy", "srcaddr", "dstaddr"
    else:
        addr_block = f"""config firewall address6
    edit "{obj}"
        set ip6 {ip}/128
    next
end"""
        policy_kw, src_kw, dst_kw = "policy6", "srcaddr", "dstaddr"
    return f"""# Fortinet FortiGate - block TOR exit node {ip} (both directions)
{addr_block}
config firewall {policy_kw}
    edit 0
        set name "Block-{obj}-in"
        set srcintf "any"
        set dstintf "any"
        set {src_kw} "{obj}"
        set {dst_kw} "all"
        set schedule "always"
        set service "ALL"
        set action deny
    next
    edit 0
        set name "Block-{obj}-out"
        set srcintf "any"
        set dstintf "any"
        set {src_kw} "all"
        set {dst_kw} "{obj}"
        set schedule "always"
        set service "ALL"
        set action deny
    next
end"""


def _juniper(ip: str) -> str:
    term = _label(ip).lower()
    family = "inet" if ipaddress.ip_address(ip).version == 4 else "inet6"
    flt = "BLOCK-TOR" if family == "inet" else "BLOCK-TOR-V6"
    cidr = _host_cidr(ip)
    return f"""# Juniper Junos - block TOR exit node {ip} (both directions)
# 'set' statements are idempotent; ensure a trailing accept-all term exists.
set firewall family {family} filter {flt} term {term}-in from source-address {cidr}
set firewall family {family} filter {flt} term {term}-in then discard
set firewall family {family} filter {flt} term {term}-out from destination-address {cidr}
set firewall family {family} filter {flt} term {term}-out then discard"""


FIREWALL_GENERATORS = {
    "cisco-ios": _cisco_ios,
    "cisco-asa": _cisco_asa,
    "checkpoint": _checkpoint,
    "ubiquiti": _ubiquiti,
    "firewalld": _firewalld,
    "fortinet": _fortinet,
    "juniper": _juniper,
}


def load_vendor_file(path: str) -> dict:
    """Load a YAML vendor file and return a dict of name -> generator callable."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "pyyaml is required for --vendor-file (pip install pyyaml).") from exc
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as exc:
        raise RuntimeError(f"Cannot read vendor file: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Invalid YAML in {path}: {exc}") from exc

    result = {}
    for name, spec in (data or {}).get("vendors", {}).items():
        prefix = spec.get("prefix", "")
        suffix = spec.get("suffix", "")
        result[name] = lambda ip, p=prefix, s=suffix: f"{p}{ip}{s}"
    return result


def firewall_rule(ip: str, fmt: str, generators: dict | None = None) -> str:
    gens = generators if generators is not None else FIREWALL_GENERATORS
    if fmt == "all":
        return "\n\n".join(gens[f](ip) for f in sorted(gens))
    return gens[fmt](ip)


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def analyse_ip(exit_ip: str, dest_ip: str | None, port: int, fmt: str | None,
               generators: dict | None = None) -> None:
    gens = generators if generators is not None else FIREWALL_GENERATORS
    version = ipaddress.ip_address(exit_ip).version
    print(f"Starting Analysis (IPv{version})")
    try:
        tor = is_tor_exit(exit_ip, dest_ip, port)
    except RuntimeError as exc:
        print(f"Something went wrong during the lookup: {exc}", file=sys.stderr)
        return

    where = (f" for {dest_ip}:{port}" if uses_dnsel(exit_ip, dest_ip)
             else " (running Exit relay)")
    if not tor:
        print(f"{exit_ip} is NOT a Tor exit{where}")
        return
    print(f"{exit_ip} IS a Tor exit{where}")

    answer = input("Generate firewall block syntax? [yes/no] ").strip().lower()
    while answer not in ("yes", "no"):
        answer = input("Yes or No: ").strip().lower()
    if answer != "yes":
        return

    if fmt is None:
        choices = sorted(gens) + ["all"]
        prompt = "Which firewall format? [" + ", ".join(choices) + "] "
        fmt = input(prompt).strip().lower()
        while fmt not in choices:
            fmt = input("Pick one of [" + ", ".join(choices) + "]: ").strip().lower()

    print()
    print(firewall_rule(exit_ip, fmt, gens))


def read_ips(path: str):
    """Yield (lineno, token) for each non-blank, non-comment line in the file."""
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            token = raw.split("#", 1)[0].strip()
            if token:
                yield lineno, token


def process_batch(path: str, dest_ip: str | None, port: int, fmt: str | None,
                  generators: dict | None = None) -> None:
    """Non-interactive: check every IP in the file and report results."""
    try:
        entries = list(read_ips(path))
    except OSError as exc:
        sys.exit(f"Cannot read {path}: {exc}")

    print(f"Batch analysis of {len(entries)} address(es) from {path}\n")
    tor_hits, checked = [], 0
    for lineno, token in entries:
        try:
            ip = str(ipaddress.ip_address(token))
        except ValueError:
            print(f"[error] line {lineno}: {token!r} is not a valid IP")
            continue
        try:
            tor = is_tor_exit(ip, dest_ip, port)
        except RuntimeError as exc:
            print(f"[error] {ip}: {exc}")
            continue
        checked += 1
        if tor:
            tor_hits.append(ip)
            print(f"[TOR]   {ip}")
        else:
            print(f"[clean] {ip}")

    print(f"\nSummary: {len(tor_hits)} Tor exit(s) out of {checked} checked")
    if fmt and tor_hits:
        print("\n# ---- Firewall block syntax for confirmed Tor exits ----")
        for ip in tor_hits:
            print()
            print(firewall_rule(ip, fmt, generators))


def valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid IP address")


def valid_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except (ipaddress.AddressValueError, ValueError):
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid IPv4 address")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check if an IPv4/IPv6 address is a Tor exit node and emit "
                    "firewall block syntax for a chosen vendor.")
    parser.add_argument("ip", type=valid_ip, nargs="?",
                        help="suspected exit-node IP (v4 or v6) to check")
    parser.add_argument("--batch", metavar="FILE", default=None,
                        help="check IPs listed one per line in FILE "
                             "(blank lines and '#' comments ignored); "
                             "runs non-interactively")
    parser.add_argument("--dest-ip", type=valid_ipv4, default=None,
                        help="optional: your destination IPv4 the exit would "
                             "connect to. Enables the precise per-port DNSEL "
                             "check for IPv4 (needs dnspython). Without it, a "
                             "relay-level Onionoo check is used; ignored for IPv6")
    parser.add_argument("--port", type=int, default=443,
                        help="destination port to test for IPv4 (default: 443)")
    parser.add_argument("--firewall-format", default=None, metavar="FMT",
                        help="vendor syntax to emit if the IP is a Tor exit "
                             "('all' dumps every vendor); built-ins: "
                             + ", ".join(sorted(FIREWALL_GENERATORS)) + ", all")
    parser.add_argument("--vendor-file", metavar="FILE", default=None,
                        help="YAML file defining custom vendor output formats "
                             "(needs pyyaml)")
    args = parser.parse_args()

    if not 0 < args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    if bool(args.ip) == bool(args.batch):
        parser.error("provide exactly one of: an IP argument or --batch FILE")

    generators = dict(FIREWALL_GENERATORS)
    if args.vendor_file:
        try:
            generators.update(load_vendor_file(args.vendor_file))
        except RuntimeError as exc:
            parser.error(str(exc))

    if args.firewall_format and args.firewall_format != "all" \
            and args.firewall_format not in generators:
        valid = sorted(generators) + ["all"]
        parser.error(
            f"--firewall-format: invalid choice {args.firewall_format!r} "
            f"(choose from: {', '.join(valid)})")

    if args.batch:
        process_batch(args.batch, args.dest_ip, args.port, args.firewall_format,
                      generators)
        return

    if args.dest_ip is not None and ipaddress.ip_address(args.ip).version == 6:
        print("Note: --dest-ip/--port are ignored for IPv6 (Onionoo is relay-level).",
              file=sys.stderr)

    analyse_ip(args.ip, args.dest_ip, args.port, args.firewall_format, generators)


if __name__ == "__main__":
    main()
