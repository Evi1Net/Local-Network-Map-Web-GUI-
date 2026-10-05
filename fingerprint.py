"""Low-impact device fingerprinting for Network Map.

Each probe is a single unicast request aimed at the device being identified:
  * mDNS / DNS-SD  (5353/udp)  - Apple model ids, printer models, cast names
  * SSDP / UPnP    (1900/udp)  - one HTTP GET of the description the device itself advertises
  * NetBIOS status (137/udp)   - Windows/Samba host name
No credentials, no exploitation, no traffic to any host except the target.
"""
from __future__ import annotations

import asyncio
import re
import socket
import struct
import time
import uuid
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

IPHONE_MODELS = {
    "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro", "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (2nd gen)", "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max", "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13", "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,6": "iPhone SE (3rd gen)", "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus", "iPhone17,5": "iPhone 16e",
}
# Host-name patterns that carry a real model; the greedy tail is bounded to known suffixes so
# "Galaxy-A54-de-Ali" yields "Galaxy A54", not the owner's name.
ANDROID_PATTERNS = (
    r"galaxy[-_ ]?(?:s|a|z|m|f|note)[-_ ]?\d+(?:[-_ ]?(?:ultra|plus|fe|lite|5g|edge))*",
    r"pixel[-_ ]?\d+[a-z]?(?:[-_ ]?(?:pro|xl|fold))*",
    r"(?:redmi|poco)[-_ ]?(?:note[-_ ]?)?\d+[a-z]*(?:[-_ ]?(?:pro|plus|5g|ultra))*",
    r"oneplus[-_ ]?(?:nord[-_ ]?)?\d+[a-z]*",
    r"realme[-_ ]?\d+[a-z]*(?:[-_ ]?pro)?",
)
MDNS_SERVICES = (
    "_companion-link._tcp.local", "_apple-mobdev2._tcp.local", "_device-info._tcp.local",
    "_airplay._tcp.local", "_googlecast._tcp.local", "_ipp._tcp.local", "_printer._tcp.local",
    "_hap._tcp.local", "_smb._tcp.local",
)
SSDP_TYPES = {"internetgatewaydevice": "router", "wanconnectiondevice": "router",
              "wlanaccesspoint": "ap", "printer": "printer"}
_MAC_RE = re.compile(r"macbook|imac|mac-?mini|mac-?pro|\bmac\d|appletv|apple-tv|homepod|windows")
_NOT_PHONE_RE = re.compile(r"(?<![a-z])tv(?![a-z])|smarttv|bravia|chromecast|nest|googlecast")
_ANDROID_VENDOR_RE = re.compile(
    r"android|samsung|xiaomi|oneplus|oppo|vivo|realme|honor|motorola|google|nothing tech|tecno|infinix|huawei device")


CAMERA_RE = re.compile(
    r"hikvision|dahua|axis communications|hanwha|techwin|uniview|uniarch|reolink|amcrest|foscam|vivotek|bosch security|"
    r"ezviz|\bimou(?![a-z])|tiandy|\bwyze(?![a-z])|\barlo(?![a-z])|\beufy(?![a-z])|lorex|swann|geovision|mobotix|avigilon|pelco|xiongmai|\btapo(?![a-z])|\bvigi(?![a-z])|"
    r"ipcam|ip-?cam|\bcam\d|camera|\bipc(?![a-z])|\bnvr(?![a-z])|\bdvr(?![a-z])|\buvc[-_ ]|unifi.?video|nest.?cam|doorbell|ring llc|ring.?cam|"
    r"annke|\bzosi(?![a-z])|trassir|beward|milesight|hiwatch|ds-2cd|ipc-hf")
MIXED_BRANDS = re.compile(r"hikvision|dahua|uniview|uniarch|hanwha|techwin|tiandy|xiongmai|lorex|swann|annke|zosi|hiwatch|ezviz|geovision|avigilon|pelco|bosch|milesight|trassir|axis")
NVR_RE = re.compile(r"(?<![a-z])(nvr|dvr|xvr|hvr|ivms|recorder)(?![a-z])|(?<![a-z0-9])(i?ds-(7[0-9]{3}|8[0-9]{3}|9[0-9]{3})[a-z]{1,2}|dhi-[nx]vr|dh-[nx]vr|[nx]vr[0-9]{3,4}|nvr[0-9]+)")
CAM_RE = re.compile(r"ds-2c[de]|ds-2cd|ds-2de|(?<![a-z])ipc[-_ ]?[a-z0-9]|dh-ipc|hf[wd][0-9]|hd[bw]{1,2}[0-9]|camera|(?<![a-z])cam[0-9 _-]|dome|bullet|(?<![a-z])ptz|turret|doorbell")
def video_kind(text: str) -> str | None:
    """'nvr' / 'camera' only on explicit evidence (model, name, web realm). A bare CCTV brand that sells both is NOT enough."""
    t = (text or "").lower()
    if NVR_RE.search(t): return "nvr"
    if CAM_RE.search(t): return "camera"
    if CAMERA_RE.search(t) and not MIXED_BRANDS.search(t): return "camera"
    return None
CAMERA_PORTS = {554, 8554, 37777, 34567}  # RTSP, Dahua, Xiongmai DVR


@dataclass
class Probe:
    """Raw answers collected from one device."""
    mdns: dict = field(default_factory=dict)
    raw: bytes = b""
    ssdp: dict = field(default_factory=dict)
    nbns: str | None = None
    onvif: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)


@dataclass
class Fingerprint:
    """Conclusion drawn from a Probe plus what is already known; every field is evidence-based."""
    platform: str | None = None   # iphone | ipad | android | apple
    model: str | None = None
    name: str | None = None
    dtype: str | None = None      # strong device-type verdict (printer, router, ap, phone ...)
    os: str | None = None
    source: str | None = None     # which probe produced the model


# ----------------------------------------------------------------------------- transport
def _udp(ip: str, port: int, payload: bytes, wait: float = 1.2) -> list[bytes]:
    """Send one datagram, collect every reply for `wait` seconds (blocking; run in a thread)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    replies: list[bytes] = []
    try:
        sock.sendto(payload, (ip, port))
        end = time.monotonic() + wait
        while time.monotonic() < end:
            replies.append(sock.recvfrom(4096)[0])
    except OSError:
        pass  # timeout ends the collection window
    finally:
        sock.close()
    return replies


# ----------------------------------------------------------------------------- mDNS
def _question(name: str) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return labels + b"\0" + struct.pack("!HH", 12, 1)  # PTR / IN


def _skip_name(buf: bytes, i: int) -> int:
    while True:
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # compression pointer
            return i + 2
        i += 1 + n


def parse_txt(packet: bytes) -> dict[str, str]:
    """Collect every key=value pair from the TXT records of a DNS packet."""
    out: dict[str, str] = {}
    try:
        qd, an, ns, ar = struct.unpack("!4H", packet[4:12])
        i = 12
        for _ in range(qd):
            i = _skip_name(packet, i) + 4
        for _ in range(an + ns + ar):
            i = _skip_name(packet, i)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", packet[i:i + 10])
            i += 10
            data, i = packet[i:i + rdlen], i + rdlen
            if rtype != 16:
                continue
            j = 0
            while j < len(data):
                n = data[j]
                item = data[j + 1:j + 1 + n].decode(errors="ignore")
                j += 1 + n
                if "=" in item:
                    k, v = item.split("=", 1)
                    out.setdefault(k, v)
    except (struct.error, IndexError):
        pass
    return out


def _mdns(ip: str) -> tuple[dict, bytes]:
    query = struct.pack("!6H", 0, 0, len(MDNS_SERVICES), 0, 0, 0) + b"".join(_question(s) for s in MDNS_SERVICES)
    packets = _udp(ip, 5353, query)  # source port != 5353 => responder answers by unicast
    merged: dict[str, str] = {}
    for p in packets:
        for k, v in parse_txt(p).items():
            merged.setdefault(k, v)
    return merged, b"".join(packets)


# ----------------------------------------------------------------------------- SSDP / UPnP
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # a device must never steer us to another host
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def parse_upnp(body: bytes) -> dict[str, str]:
    """Extract identity fields from a UPnP device description (DTD/entities rejected)."""
    if b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        return {}
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return {}
    wanted = ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType")
    out: dict[str, str] = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in wanted and el.text and el.text.strip():
            out.setdefault(tag, el.text.strip())
    return out


def _ssdp(ip: str) -> dict:
    request = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
               'MX: 1\r\nST: upnp:rootdevice\r\n\r\n').encode()
    for packet in _udp(ip, 1900, request):
        m = re.search(rb"(?im)^location:\s*(\S+)", packet)
        if not m:
            continue
        url = m[1].decode(errors="ignore")
        u = urllib.parse.urlparse(url)
        if u.scheme != "http" or u.hostname != ip:
            continue
        try:
            with _OPENER.open(url, timeout=2) as r:
                info = parse_upnp(r.read(65536))
        except Exception:
            continue
        if info:
            return info
    return {}


# ----------------------------------------------------------------------------- NetBIOS
def parse_nbns(data: bytes) -> str | None:
    """First unique workstation name (suffix 0x00) of a node-status reply."""
    try:
        for k in range(data[56]):
            o = 57 + 18 * k
            name, suffix, flags = data[o:o + 15].decode("ascii", "ignore").strip(), data[o + 15], data[o + 16]
            if suffix == 0 and not flags & 0x80 and name:
                return name
    except IndexError:
        pass
    return None


def _nbns(ip: str) -> str | None:
    query = struct.pack("!6H", 0x1234, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"AA" * 15 + b"\x00" + struct.pack("!HH", 0x21, 1)
    for d in _udp(ip, 137, query, 1.0):
        n = parse_nbns(d)
        if n:
            return n
    return None


_WSD = ('<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:{}</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
        '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>')


def parse_onvif(body: bytes) -> dict[str, str]:
    """WS-Discovery ProbeMatch -> {name, hardware, location, types}; empty if the device is not ONVIF."""
    txt = body.decode(errors="ignore")
    if "<!DOCTYPE" in txt or "<!ENTITY" in txt or "onvif" not in txt.lower():
        return {}
    scopes = re.search(r"Scopes[^>]*>([^<]+)<", txt)
    if not scopes:
        return {}
    out = {"types": (re.search(r"Types[^>]*>([^<]+)<", txt) or [None, ""])[1]}
    for tok in scopes[1].split():
        m = re.match(r"onvif://www\.onvif\.org/(name|hardware|location)/(.+)", tok)
        if m:
            out[m[1]] = urllib.parse.unquote(m[2])
    return out


def _onvif(ip: str) -> dict:
    for packet in _udp(ip, 3702, _WSD.format(uuid.uuid4()).encode(), 1.2):
        info = parse_onvif(packet)
        if info:
            return info
    return {}


def _http(ip: str) -> dict:
    """GET / on 80/443/8000: page title, Server header and 401 realm (Hikvision/Dahua put the model there)."""
    import http.client, ssl
    for port, tls in ((80, 0), (443, 1), (8000, 0)):
        try:
            c = (http.client.HTTPSConnection(ip, port, timeout=2, context=ssl._create_unverified_context()) if tls
                 else http.client.HTTPConnection(ip, port, timeout=2))
            c.request("GET", "/", headers={"User-Agent": "netmap"})
            r = c.getresponse(); body = r.read(4096).decode(errors="ignore"); c.close()
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            out = {"title": (m[1].strip()[:80] if m else ""), "server": r.getheader("Server") or "", "realm": r.getheader("WWW-Authenticate") or ""}
            if any(out.values()): return out
        except Exception:
            pass
    return {}


async def gather(ip: str) -> Probe:
    """Run all probes concurrently; a failing probe only contributes nothing."""
    res = await asyncio.gather(*(asyncio.to_thread(fn, ip) for fn in (_mdns, _ssdp, _nbns, _onvif, _http)), return_exceptions=True)
    md, raw = res[0] if not isinstance(res[0], Exception) else ({}, b"")
    ok = lambda v, t: v if isinstance(v, t) else t() if t is not str else None
    return Probe(md, raw, ok(res[1], dict), ok(res[2], str), ok(res[3], dict), ok(res[4], dict))


# ----------------------------------------------------------------------------- reasoning
def _fp(f: Fingerprint, platform: str | None, model: str | None, source: str) -> Fingerprint:
    f.platform, f.model, f.source = platform, model or f.model, source
    if platform in ("iphone", "ipad"):
        f.dtype, f.os = "phone", "iPadOS" if platform == "ipad" else "iOS"
    elif platform == "android":
        f.dtype, f.os = "phone", "Android"
    return f


def _identify(vendor: str, hostname: str, ports: list[int], os_: str, pr: Probe) -> Fingerprint:
    """Priority: mDNS (device-declared) > SSDP (device-declared) > host name > vendor."""
    f, md, raw, sd = Fingerprint(), pr.mdns, pr.raw, pr.ssdp
    hn = hostname or ""
    text = f"{vendor} {hn} {os_} {sd.get('manufacturer', '')} {sd.get('modelName', '')}".lower()
    f.name = md.get("fn") or sd.get("friendlyName") or pr.nbns
    web = f"{pr.http.get('title','')} {pr.http.get('server','')} {pr.http.get('realm','')}"
    text += " " + web.lower()
    ports_set = set(ports)

    if pr.onvif:  # declares itself a video device; NVR or camera is decided by model/name only
        f.model = pr.onvif.get("hardware") or pr.onvif.get("name")
        f.name = f.name or pr.onvif.get("name")
        f.source = "ONVIF"
        f.dtype = video_kind(f"{f.model} {pr.onvif.get('name','')} {text}")
        if f.dtype: return f
    k = video_kind(text)
    if k:
        f.dtype, f.model = k, f.model or sd.get("modelName")
        f.source = f.source or ("SSDP" if f.model else "model/name")
        return f

    printer = md.get("ty") or md.get("usb_MDL") or md.get("product", "").strip("()")
    if printer or SSDP_TYPES.get(_ssdp_type(sd)) == "printer":
        f.dtype, f.model = "printer", printer or sd.get("modelName")
        f.source = "mDNS" if printer else "SSDP"
        return f

    apple = md.get("rpMd") or md.get("model") or md.get("am") or ""
    if apple.startswith("iPhone"):
        return _fp(f, "iphone", IPHONE_MODELS.get(apple, apple), "mDNS")
    if apple.startswith("iPad"):
        return _fp(f, "ipad", apple, "mDNS")
    if apple.startswith(("Mac", "AppleTV", "AudioAccessory", "Watch")) or _MAC_RE.search(text):
        if apple:
            f.model, f.source = apple, "mDNS"
        return f
    if b"iPhone" in raw or b"apple-mobdev2" in raw or 62078 in ports or "iphone" in text or "ios" in os_.lower().split():
        return _fp(f, "iphone", None, "mDNS" if raw else "hostname/port")
    if "ipad" in text or b"iPad" in raw:
        return _fp(f, "ipad", None, "mDNS" if raw else "hostname")

    if sd.get("modelName"):
        model = sd["modelName"]
        if sd.get("modelNumber") and sd["modelNumber"] not in model:
            model += f" {sd['modelNumber']}"
        f.model, f.source, f.dtype = model, "SSDP", SSDP_TYPES.get(_ssdp_type(sd))
        return f

    code = re.search(r"\b(SM-[A-Z]\d{3,4}[A-Z0-9]{0,3})\b", hn, re.I)
    if code:
        return _fp(f, "android", "Samsung " + code[1].upper(), "hostname")
    for pattern in ANDROID_PATTERNS:
        m = re.search(pattern, hn, re.I)
        if m:
            return _fp(f, "android", re.sub(r"[-_]+", " ", m[0]).title().strip(), "hostname")
    if _NOT_PHONE_RE.search(text) or b"googlecast" in raw:
        return f
    return f


def _ssdp_type(sd: dict) -> str:
    parts = sd.get("deviceType", "").split(":")
    return parts[-2].lower() if len(parts) >= 2 else ""


def identify(vendor, hostname, ports, os_, pr):
    """_identify + OS/computer icons: only from an explicit OS string, model id or host name."""
    f = _identify(vendor, hostname, ports, os_, pr)
    if f.dtype: return f
    t = f"{hostname} {os_} {pr.mdns.get('rpMd','')} {pr.mdns.get('model','')}".lower()
    if re.search(r"appletv|apple-tv", t): f.dtype = "tv"
    elif re.search(r"macbook|imac|mac-?mini|mac-?pro|mac studio|mac os|macos|os x|(?<![a-z])mac[0-9]", t): f.dtype = "mac"
    elif "windows" in t or re.search(r"(?<![a-z])(desktop|laptop)-[a-z0-9]{5,}", t): f.dtype = "windows"
    elif re.search(r"ubuntu|debian|fedora|centos|raspberry|linux", t) and "android" not in t: f.dtype = "linux"
    if f.dtype and not f.source: f.source = "OS/hostname"
    return f
