"""Physical-topology inference from managed-switch MAC tables (SNMP BRIDGE-MIB / Q-BRIDGE-MIB).

A switch that has learned a device's MAC on a port tells us the device is somewhere behind that port.
The port with the FEWEST learned MACs is the closest one (an access port); ports that also carry the
gateway's MAC lead *upstream* and are ignored. If the group of MACs on the chosen port contains exactly
one access point, wireless clients are attached to that AP rather than to the switch.
"""
from __future__ import annotations

import asyncio
import re
from collections import defaultdict

OID_FDB_Q = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # dot1qTpFdbPort  (VLAN-aware switches)
OID_FDB_D = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort  (classic bridges)
OID_BRPORT_IF = "1.3.6.1.2.1.17.1.4.1.2"    # dot1dBasePortIfIndex
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
INFRA = {"switch", "router", "firewall", "ap"}
_LINE = re.compile(r"^\.?([\d.]+) = [\w-]+: ?(.*)$")


def parse_walk(text: str, base: str) -> list[tuple[tuple[int, ...], str]]:
    """`snmpwalk -On` output -> [(index tuple relative to `base`, value)]."""
    pre, out = base.lstrip(".") + ".", []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m or not m[1].startswith(pre):
            continue
        try:
            out.append((tuple(int(x) for x in m[1][len(pre):].split(".")), m[2].strip().strip('"')))
        except ValueError:
            continue
    return out


async def walk(ip: str, community: str, oid: str, timeout: float = 15) -> str:
    p = None
    try:
        p = await asyncio.create_subprocess_exec("snmpwalk", "-v2c", "-c", community, "-t", "1", "-r", "1",
                                                 "-On", ip, oid, stdout=-1, stderr=-3)
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
        return out.decode(errors="replace")
    except Exception:
        if p and p.returncode is None:
            try:
                p.kill()
            except ProcessLookupError:
                pass
        return ""


async def collect_fdb(ip: str, community: str) -> list[tuple[str, str]]:
    """[(mac, port label)] learned by one switch; [] if it exposes no bridge table."""
    q, d, bp, nm, ds = await asyncio.gather(*(walk(ip, community, o) for o in
                                              (OID_FDB_Q, OID_FDB_D, OID_BRPORT_IF, OID_IFNAME, OID_IFDESCR)))
    entries = parse_walk(q, OID_FDB_Q) + parse_walk(d, OID_FDB_D)
    if not entries:
        return []
    to_if = {s[0]: int(v) for s, v in parse_walk(bp, OID_BRPORT_IF) if v.isdigit()}
    names = {s[0]: v for s, v in parse_walk(nm, OID_IFNAME)}
    for s, v in parse_walk(ds, OID_IFDESCR):
        names.setdefault(s[0], v)
    out = []
    for idx, val in entries:
        if len(idx) < 6 or not val.isdigit() or int(val) == 0:  # port 0 = the switch itself
            continue
        port = int(val)
        out.append((":".join(f"{n:02x}" for n in idx[-6:]), names.get(to_if.get(port), f"port {port}")))
    return out


def assign_parents(devs: list[dict], fdbs: dict[int, list[tuple[str, str]]], gw: int | None = None) -> dict[int, tuple[int, str]]:
    """devs: [{id, mac, type}], fdbs: {switch_id: [(mac, port)]} -> {child_id: (parent_id, port label)}."""
    by = {d["id"]: d for d in devs}
    by_mac = {d["mac"].lower(): d for d in devs if d.get("mac")}
    gmac = (by[gw].get("mac") or "").lower() if gw in by else ""
    group: dict[tuple, set] = defaultdict(set)
    where: dict[str, list] = defaultdict(list)
    for sw, rows in fdbs.items():
        for mac, port in rows:
            mac = mac.lower()
            group[(sw, port)].add(mac)
            where[mac].append((sw, port))
    out: dict[int, tuple[int, str]] = {}
    for d in devs:
        m = (d.get("mac") or "").lower()
        if not m or d["id"] == gw:
            continue
        # ports that also carry the gateway MAC point upstream: d is not "behind" them
        cands = [(len(group[k]), k) for k in where.get(m, []) if k[0] != d["id"] and not (gmac and gmac in group[k])]
        if cands:
            _, (sw, port) = min(cands, key=lambda c: (c[0], c[1][0]))
            parent, info = sw, port
            if d["type"] not in INFRA:
                aps = [by_mac[x]["id"] for x in group[(sw, port)]
                       if x in by_mac and by_mac[x]["type"] == "ap" and by_mac[x]["id"] != sw]
                if len(aps) == 1:
                    parent, info = aps[0], "Wi-Fi via AP"
            out[d["id"]] = (parent, info)
        elif gmac and d["type"] in INFRA:  # switch whose only neighbour on a port is the gateway
            for k in (k for k in where.get(gmac, []) if k[0] == d["id"]):
                if len(group[k]) == 1:
                    out[d["id"]] = (gw, k[1])
    return out


def parse_lldp(frame: bytes) -> dict:
    """Ethernet frame (ethertype 0x88cc) -> {chassis, port, name, desc, mgmt}; what the directly attached switch announces."""
    out: dict = {}
    i = 14
    while i + 2 <= len(frame):
        head = (frame[i] << 8) | frame[i + 1]
        t, n = head >> 9, head & 0x1FF
        v = frame[i + 2:i + 2 + n]
        i += 2 + n
        if t == 0:
            break
        if t == 1 and v[:1] == b"\x04":
            out["chassis"] = ":".join(f"{b:02x}" for b in v[1:7])
        elif t == 2:
            out["port"] = ":".join(f"{b:02x}" for b in v[1:]) if v[:1] == b"\x03" else v[1:].decode(errors="ignore")
        elif t == 5:
            out["name"] = v.decode(errors="ignore")
        elif t == 6:
            out["desc"] = v.decode(errors="ignore")[:200]
        elif t == 8 and len(v) >= 6 and v[0] >= 5 and v[1] == 1:
            out["mgmt"] = ".".join(str(b) for b in v[2:6])
    return out
