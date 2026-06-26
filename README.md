# tor_check.py

Check whether an IPv4 or IPv6 address is a **Tor exit node**, and optionally emit
ready-to-paste **firewall block syntax** for a range of vendors.

Originally a PowerShell script that used the Tor DNSEL and `New-NetFirewallRule`;
this is a cross-platform Python rewrite that fixes the original's validation and
error-handling gaps, adds IPv6 support, multi-vendor rule generation, and a batch
mode.

---

## How detection works

The lookup method is chosen automatically:

| Condition | Method | Precision |
|-----------|--------|-----------|
| IPv4 **with** `--dest-ip` | Tor DNS Exit List, `ip-port` service | Per `dest_ip:port` — *"can this exit reach my service?"* |
| IPv4 without `--dest-ip`, or any IPv6 | [Onionoo](https://onionoo.torproject.org/) details API | Relay-level — *"is this a running relay with the `Exit` flag?"* |

**The minimum command is just an IP** — `python3 tor_check.py 1.2.3.4` — which
runs the relay-level Onionoo check for either family. Supplying `--dest-ip`
*upgrades* an IPv4 check to the more precise DNSEL `ip-port` lookup.

**Why two methods?** The Tor DNSEL has no IPv6 zone and requires a destination to
answer its per-`dest:port` question. Onionoo covers both families with no extra
input, but only at the relay level. So `--dest-ip` buys precision for IPv4 when
you have a specific destination in mind; otherwise Onionoo is the sensible
default.

- **IPv4 query format:** `<reversed-exit-ip>.<port>.<reversed-dest-ip>.ip-port.exitlist.torproject.org`
  — a match resolves to `127.0.0.2`.
- **Onionoo** requires **no API key** (public, read-only, fair-use rate limited).

---

## Requirements

- **Python 3.10+** (uses `X | None` type-hint syntax).
- **dnspython** — only needed for the precise IPv4 DNSEL path (`--dest-ip`):
  ```bash
  pip install -r requirements.txt
  ```
  The default Onionoo path (any check without `--dest-ip`, plus all IPv6) is
  standard-library only (`urllib`). Run without `--dest-ip` and you need no
  third-party packages at all.

---

## Usage

```
tor_check.py [ip] [--batch FILE] [--dest-ip IP] [--port N] [--firewall-format FMT]
```

| Argument | Description |
|----------|-------------|
| `ip` | A single IPv4/IPv6 address to check. Mutually exclusive with `--batch`. |
| `--batch FILE` | Check many IPs listed in a file (see [Batch mode](#batch-mode)). |
| `--dest-ip IP` | *Optional.* Destination IPv4 the exit would connect to. Upgrades an IPv4 check to the precise DNSEL `ip-port` lookup (needs dnspython). Ignored for IPv6. |
| `--port N` | Destination port for the DNSEL check (default: `443`; only used with `--dest-ip`). |
| `--firewall-format FMT` | Vendor syntax to emit for confirmed exits. One of the [supported formats](#firewall-formats) or `all`. |

Exactly one of `ip` or `--batch` must be provided.

### Single-IP mode

Interactive: if the IP is a confirmed Tor exit, you're prompted before any
firewall syntax is printed.

```bash
# Minimum command — relay-level Onionoo check (no extra args, no dnspython)
python3 tor_check.py 171.25.193.77

# IPv4 with precise per-port DNSEL check (needs dnspython)
python3 tor_check.py 1.2.3.4 --dest-ip 203.0.113.9 --port 80

# IPv6 — Onionoo; --dest-ip/--port not needed (ignored with a notice if given)
python3 tor_check.py 2001:db8::1 --firewall-format firewalld
```

### Batch mode

Non-interactive — designed for scripting/cron. Reads one IP per line; blank lines
and `#` comments (whole-line or trailing) are ignored. IPv4 and IPv6 may be mixed
in the same file.

`ips.txt`:
```
# Tor candidates to check
1.2.3.4        # trailing comments work too
2001:db8::1
9.9.9.9
```

```bash
# Report status only
python3 tor_check.py --batch ips.txt --dest-ip 203.0.113.9 --port 443

# Report status, then dump block syntax for every confirmed exit
python3 tor_check.py --batch ips.txt --dest-ip 203.0.113.9 --firewall-format all
```

Example output:
```
Batch analysis of 3 address(es) from ips.txt

[TOR]   1.2.3.4
[clean] 9.9.9.9
[TOR]   2001:db8::1

Summary: 2 Tor exit(s) out of 3 checked
```

Each line is `[TOR]`, `[clean]`, or `[error]`. An invalid IP, a lookup failure,
or an IPv4 entry with no `--dest-ip` is reported as `[error]` and the batch
continues.

---

## Firewall formats

`--firewall-format` emits block configuration for the chosen platform. Every
generator:

- blocks the address in **both directions** (as source *and* destination), and
- is **idempotent** — it reuses deterministic, IP-derived object/rule names and
  structures the platform treats as no-ops on re-apply.

Both IPv4 and IPv6 variants are produced as appropriate.

| Value | Platform | IPv6 handling |
|-------|----------|---------------|
| `cisco-ios` | Cisco IOS extended ACL | `ipv6 access-list` |
| `cisco-asa` | Cisco ASA object + ACL | unified ACL (requires ASA 9.0+) |
| `checkpoint` | Check Point `mgmt_cli` | `ipv6-address` |
| `ubiquiti` | Ubiquiti EdgeOS | `ipv6-address-group` / `ipv6-name` |
| `firewalld` | firewalld rich rules | `family="ipv6"` |
| `fortinet` | Fortinet FortiGate | `address6` / `policy6` |
| `juniper` | Juniper Junos filter | `family inet6` |
| `all` | dumps every vendor above | — |

> **Note:** the generated rules are *config syntax to paste into your device* —
> the script does not apply them. A couple of vendors assume a sensible default
> policy already exists (e.g. the Juniper filter needs a trailing accept-all term,
> Cisco ACLs an explicit `permit` where appropriate) or you may block more than
> intended.

---

## Caveats

- **IPv6 precision:** the IPv6 check is relay-level, not per-`dest:port`. It flags
  any running relay carrying the `Exit` flag whose address matches.
- **Batch + IPv6 volume:** each IPv6 entry is a separate Onionoo request. Fine for
  fair-use, but for very large IPv6 lists a single bulk fetch with local matching
  would be friendlier — not currently implemented.
- **Accuracy depends on upstream data** (Tor DNSEL / Onionoo); a relay that just
  changed state may not be reflected immediately.

---

## Exit behavior

- Invalid IP arguments are rejected by `argparse` before any lookup.
- Missing/unsupported `dnspython` produces a clear install hint (IPv4 path only).
- A missing batch file fails with the OS error message, not a traceback.
