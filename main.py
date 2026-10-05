import asyncio,ipaddress,json,os,re,sqlite3,time,collections,xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from fastapi import FastAPI,WebSocket,WebSocketDisconnect,HTTPException
from fastapi.responses import FileResponse,StreamingResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from fingerprint import gather,identify,Probe,CAMERA_RE,CAMERA_PORTS,video_kind
from topology import collect_fdb,assign_parents,parse_lldp
B=os.path.dirname(os.path.abspath(__file__));os.makedirs(B+"/data",exist_ok=True)
db=sqlite3.connect(B+"/data/network.db",check_same_thread=False);db.row_factory=sqlite3.Row
db.executescript("""CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY,ip TEXT,mac TEXT,vendor TEXT,hostname TEXT,type TEXT DEFAULT 'unknown',os TEXT,ports TEXT DEFAULT '[]',first_seen REAL,last_seen REAL,state TEXT DEFAULT 'online',state_since REAL,notes TEXT DEFAULT '',conn TEXT DEFAULT 'unknown',conn_override TEXT,evidence TEXT DEFAULT '[]',lat REAL,jit REAL,loss REAL DEFAULT 0,x REAL,y REAL,snmp TEXT,manual INT DEFAULT 0,ttl INT);
CREATE TABLE IF NOT EXISTS deleted(k TEXT PRIMARY KEY);CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS links(a INT,b INT,PRIMARY KEY(a,b));
CREATE TABLE IF NOT EXISTS uplinks(child INTEGER PRIMARY KEY,parent INT,info TEXT,ts REAL);""")
for _c,_t in(("model","TEXT"),("platform","TEXT"),("alias","TEXT"),("color","TEXT"),("id_src","TEXT"),("type_locked","INT DEFAULT 0"),("enriched","REAL"),("scanned","REAL"),("manual_parent","INT")):
    try:db.execute(f"ALTER TABLE devices ADD COLUMN {_c} {_t}")
    except sqlite3.OperationalError:pass
DEF={"routed":"0","cidrs":"","interval":"30","infer":"1","snmp_community":"","autoscan":"1","autoroutes":"0","npos":"{}","active":"0"}
SC={"run":0,"phase":"","done":0,"total":0};DL=asyncio.Lock()
def active():return S("active")=="1"
def S(k):
    r=db.execute("SELECT v FROM settings WHERE k=?",(k,)).fetchone();return r[0] if r else DEF[k]
BAD=re.compile(r"^(lo|docker|veth|br-|virbr|tun|tap|tailscale|wg|vpn|zt|ppp)")
clients=set();events=collections.deque(maxlen=200);st={};kick=asyncio.Event()
async def bc(m):
    for c in list(clients):
        try:await c.send_text(json.dumps(m))
        except Exception:clients.discard(c)
def ev(kind,msg,did=None):
    e={"t":"event","ts":time.time(),"kind":kind,"msg":msg,"id":did};events.appendleft(e);return bc(e)
async def run(c,t=30):
    p=None
    try:
        p=await asyncio.create_subprocess_exec(*c,stdout=-1,stderr=-1);o,_=await asyncio.wait_for(p.communicate(),t);return o.decode(errors="replace")
    except Exception:
        try:p.kill()
        except Exception:pass
        return ""
def D(r):
    d=dict(r)
    for k in("ports","evidence"):d[k]=json.loads(d[k] or "[]")
    d["snmp"]=json.loads(d["snmp"]) if d["snmp"] else None;d["conn_eff"]=d["conn_override"] or d["conn"];return d
MAX_ADDR=65536
def _octets(tok):
    """'192.168.0-12.1-254' -> [(192,192),(168,168),(0,12),(1,254)]"""
    parts=tok.split(".")
    if len(parts)!=4 or not all(re.fullmatch(r"\d{1,3}(-\d{1,3})?",p) for p in parts):raise ValueError(tok)
    out=[]
    for p in parts:
        lo,_,hi=p.partition("-");lo=int(lo);hi=int(hi or lo)
        if not 0<=lo<=hi<=255:raise ValueError(tok)
        out.append((lo,hi))
    return out
def _ranges(tok):
    """One token -> list of (first,last) IPv4 integers. Accepts CIDR, a.b.c.d-e.f.g.h, a.b.c.d-N, per-octet ranges, single IPs."""
    I=lambda x:int(ipaddress.IPv4Address(x))
    if"/"in tok:
        n=ipaddress.ip_network(tok,strict=False)
        if n.version!=4:raise ValueError(tok)
        return[(int(n.network_address),int(n.broadcast_address))]
    if tok.count("-")==1 and tok.split("-")[1].count(".")==3:
        lo,hi=map(I,tok.split("-"))
        if lo>hi:raise ValueError(tok)
        return[(lo,hi)]
    o=_octets(tok)
    if(o[0][1]-o[0][0]+1)*(o[1][1]-o[1][0]+1)*(o[2][1]-o[2][0]+1)>4096:raise ValueError(tok)
    return[(I(f"{a}.{b}.{c}.{o[3][0]}"),I(f"{a}.{b}.{c}.{o[3][1]}")) for a in range(o[0][0],o[0][1]+1) for b in range(o[1][0],o[1][1]+1) for c in range(o[2][0],o[2][1]+1)]
def expand_targets(text):
    """Setting text -> (nmap targets split per /24, invalid tokens, address count, truncated, merged ranges)."""
    rs=[];bad=[]
    for tok in filter(None,re.split(r"[,\s;]+",text or"")):
        try:rs+=_ranges(tok)
        except ValueError:bad.append(tok)
    merged=[]
    for lo,hi in sorted(rs):
        if merged and lo<=merged[-1][1]+1:merged[-1]=(merged[-1][0],max(merged[-1][1],hi))
        else:merged.append((lo,hi))
    targets=[];total=0;trunc=False
    for lo,hi in merged:
        for c in range(lo>>8,(hi>>8)+1):
            base=c<<8;a=max(lo,base)-base;b=min(hi,base+255)-base
            if total+b-a+1>MAX_ADDR:trunc=True;break
            pre=str(ipaddress.IPv4Address(base)).rsplit(".",1)[0];total+=b-a+1
            targets.append(f"{pre}.0/24" if(a,b)==(0,255) else f"{pre}.{a}-{b}")
    ip=lambda n:str(ipaddress.IPv4Address(n))
    return targets,bad,total,trunc,[f"{ip(lo)} – {ip(hi)}" for lo,hi in merged]
def in_target(ip,t):
    """Is `ip` inside a CIDR or an 'a.b.c.lo-hi' target?"""
    if"/"in t:return ipaddress.ip_address(ip) in ipaddress.ip_network(t)
    base,_,rng=t.rpartition(".");lo,_,hi=rng.partition("-");pre,_,last=ip.rpartition(".")
    return pre==base and int(lo)<=int(last)<=int(hi or lo)
async def route_nets():
    """Private networks this host reaches through a gateway (static routes): they exist, but are not directly connected."""
    out=[]
    for r in json.loads(await run(["ip","-j","-4","route","show"]) or"[]"):
        d=r.get("dst","")
        if d=="default" or not r.get("gateway") or BAD.match(r.get("dev","")):continue
        try:n=ipaddress.ip_network(d,strict=False)
        except ValueError:continue
        if n.is_private and 16<=n.prefixlen<32:out.append({"cidr":str(n),"gateway":r["gateway"],"dev":r.get("dev")})
    return out
def alive_nets(xml_text,skip):
    """nmap XML of probed gateway addresses -> the /24 networks that answered (minus already scanned ones)."""
    found={}
    for h in ET.fromstring(xml_text).findall("host"):
        if h.find("status").get("state")!="up":continue
        ip=next((a.get("addr") for a in h.findall("address") if a.get("addrtype")=="ipv4"),None)
        net=ip.rsplit(".",1)[0]+".0/24" if ip else None
        if net and net not in skip:found.setdefault(net,[]).append(ip)
    return[{"net":n,"alive":v} for n,v in sorted(found.items(),key=lambda kv:ipaddress.ip_network(kv[0]))]
async def local():
    nets=[];own=set();macs=set()
    for i in json.loads(await run(["ip","-j","-4","addr"]) or "[]"):
        if BAD.match(i["ifname"]):continue
        macs.add((i.get("address") or "").lower());_a=[a["local"] for a in i.get("addr_info",[])];IFS[i["ifname"]]={"mac":i.get("address") or"","ip":_a[0] if _a else None}
        for a in i.get("addr_info",[]):
            n=ipaddress.ip_interface(f'{a["local"]}/{a["prefixlen"]}').network;own.add(a["local"])
            if n.num_addresses<=1024:nets.append((str(n),False))
    if S("routed")=="1":
        direct={n for n,_ in nets}
        want=expand_targets(S("cidrs"))[0]
        if S("autoroutes")=="1":want+=[t for r in await route_nets() for t in expand_targets(r["cidr"])[0]]
        nets+=[(t,True) for t in dict.fromkeys(want) if t not in direct]
    return nets,own,macs
def classify(v,hn,ports,os_,ttl=None,mac=None):
    """Only definite evidence (vendor brand of a single-purpose product, hostname/model text, characteristic ports). Otherwise 'unknown' - never a guess from TTL, port 22 or a generic vendor."""
    t=f"{v} {hn} {os_}".lower();nm=f"{hn} {os_}".lower();p=set(ports)
    vk=video_kind(t)
    if vk:return vk
    if re.search(r"printer|epson|brother|canon|xerox|lexmark|hp inc|hewlett",t) or p&{9100,631}:return"printer"
    if re.search(r"fortinet|palo alto|sophos|pfsense|opnsense|sonicwall|watchguard",t):return"firewall"
    if re.search(r"unifi|access ?point|(?<![a-z])ap(?![a-z])|(?<![a-z])uap|aruba instant|ruckus.*(zone|ap)|cambium",nm):return"ap"
    if re.search(r"switch|catalyst|(?<![a-z])sw[-_ ]?\d|procurve|aruba.*(2530|2930)",nm):return"switch"
    if re.search(r"router|routerboard|mikrotik|openwrt|keenetic|gateway",nm):return"router"
    if re.search(r"(?<![a-z])tv(?![a-z])|smarttv|bravia|webos|tizen|roku|chromecast|apple-?tv|appletv|fire-?tv|android-?tv|vizio|hisense|(?<![a-z])tcl(?![a-z])",t):return"tv"
    if re.search(r"synology|qnap|asustor|terramaster|readynas|my ?cloud|diskstation",t):return"nas"
    if re.search(r"espressif|tuya|shelly|sonoff|itead|tasmota|broadlink|yeelight|(?<![a-z])wiz(?![a-z])|sonos|lifx|signify|roborock|meross|ewelink|smart ?plug|thermostat",t):return"iot"
    if 62078 in p or re.search(r"iphone|ipad|android|galaxy|pixel|oneplus|redmi|poco|realme",nm):return"phone"
    if re.search(r"macbook|imac|mac-?mini|mac-?pro|macos|mac os",nm):return"mac"
    if "windows" in nm or 3389 in p or {135,445}<=p:return"windows"
    if re.search(r"linux|ubuntu|debian|raspberry",nm):return"linux"
    return"unknown"
def conn(d):
    ev_=[];s=0;t=d["type"];m=d["mac"] or""
    u=db.execute("SELECT info FROM uplinks WHERE child=?",(d["id"],)).fetchone()
    if u:return("wifi",["switch MAC cədvəli: AP arxasında"]) if str(u[0]).startswith("Wi-Fi") else("lan",["switch portunda öyrənilib: "+str(u[0])])
    if t=="phone":s+=2;ev_.append("device type: phone")
    if t in("server","nas","switch","router","firewall","printer","windows","ap"):s-=1;ev_.append(f"device type: {t}")
    if len(m)>1 and int(m[1],16)&2:s+=2;ev_.append("private/randomized MAC")
    if (d["jit"] or 0)>15:s+=1;ev_.append(f"jitter {d['jit']:.0f} ms")
    if re.search(r"espressif|apple|samsung|intel corporate|murata|liteon",(d["vendor"] or"").lower()):s+=1;ev_.append(f"vendor: {d['vendor']}")
    if db.execute("SELECT 1 FROM links WHERE a=? OR b=?",(d["id"],d["id"])).fetchone():s-=3;ev_.append("LLDP/CDP link")
    return("wifi" if s>=3 else"lan" if s<0 or t in("server","nas","switch","router","windows","printer") else"unknown"),ev_
async def discover():
    async with DL:await _discover()
async def _discover():
    nets,own,lm=await local();seen={}
    sem=asyncio.Semaphore(4)  # ranges are swept four /24 chunks at a time
    async def sweep(n,routed):
        async with sem:return await run(["nmap","-sn","-R","-T4","-oX","-"]+(["-PE","-PS22,80,443,445"] if routed else[])+[n],180)
    outs=await asyncio.gather(*[sweep(n,r) for n,r in nets])
    for (n,routed),x in zip(nets,outs):
        try:root=ET.fromstring(x)
        except ET.ParseError:continue
        for h in root.findall("host"):
            if h.find("status").get("state")!="up":continue
            ip=mac=ven=None
            for a in h.findall("address"):
                if a.get("addrtype")=="ipv4":ip=a.get("addr")
                elif a.get("addrtype")=="mac":mac=a.get("addr").lower();ven=a.get("vendor")
            hn=h.find("hostnames/hostname")
            if ip and ip not in own and mac not in lm:seen.setdefault(mac or ip,[]).append((ip,ven,hn.get("name") if hn is not None else None))
    now=time.time()
    for k,v in seen.items():
        mac=k if":"in k else None;ips=[e[0] for e in v];row=db.execute("SELECT * FROM devices WHERE mac=?",(k,)).fetchone() if mac else db.execute("SELECT * FROM devices WHERE ip=?",(k,)).fetchone()
        ip=row["ip"] if row and row["ip"] in ips else sorted(ips,key=ipaddress.ip_address)[0]  # proxy-ARP aliases collapse to one IP
        e=[x for x in v if x[0]==ip][0]
        if db.execute("SELECT 1 FROM deleted WHERE k IN(?,?)",(mac or ip,ip)).fetchone():continue
        if row:
            if row["ip"]!=ip:await ev("info",f"{row['hostname'] or row['mac']} changed IP {row['ip']} → {ip}",row["id"])
            db.execute("UPDATE devices SET ip=?,vendor=COALESCE(?,vendor),hostname=COALESCE(?,hostname) WHERE id=?",(ip,e[1],e[2],row["id"]))
        else:
            c=db.execute("INSERT INTO devices(ip,mac,vendor,hostname,type,first_seen,last_seen,state_since) VALUES(?,?,?,?,?,?,?,?)",(ip,mac,e[1],e[2],classify(e[1] or"",e[2] or"",[],"",None,mac),now,now,now));await ev("new",f"New device {ip} {e[1] or''}",c.lastrowid)
    if nets:
        for r in db.execute("SELECT id,ip FROM devices WHERE manual=0").fetchall():
            if not any(in_target(r["ip"],n) for n,_ in nets):db.execute("DELETE FROM devices WHERE id=?",(r["id"],))
    gw=(json.loads(await run(["ip","-j","route","show","default"]) or"[]") or[{}])[0].get("gateway")
    for r in db.execute("SELECT * FROM devices WHERE type='unknown'").fetchall():
        t="router" if r["ip"]==gw else classify(r["vendor"] or"",r["hostname"] or"",[p["port"] for p in json.loads(r["ports"] or"[]")],r["os"] or"",r["ttl"],r["mac"])
        if t!="unknown":db.execute("UPDATE devices SET type=? WHERE id=?",(t,r["id"]))
    await enrich_all()
    db.commit();await bc({"t":"refresh"})
LLDP_SEEN={}  # interface -> what the directly attached switch announced (passive, receive-only)
def _lldp_rx(k):
    try:return k.recvfrom(2048)
    except socket.timeout:return None
async def lldp_listen():
    """Passively listen for LLDP frames: the switch this server is plugged into announces its name and port."""
    while not active():await asyncio.sleep(2)
    await local()
    try:
        k=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88cc));k.settimeout(2)
        for dev in list(IFS):
            try:k.setsockopt(263,1,struct.pack("iHH8s",socket.if_nametoindex(dev),2,0,b""))  # PACKET_MR_ALLMULTI
            except OSError:pass
    except OSError:return
    while True:
        try:
            r=await asyncio.to_thread(_lldp_rx,k)
            if r:
                info=parse_lldp(r[0])
                if info.get("chassis") or info.get("mgmt"):LLDP_SEEN[r[1][0]]={**info,"ts":time.time()}
        except Exception:await asyncio.sleep(2)
SNMPRETRY={};FDB={}
async def snmp_one(r,cm):
    """System, interface, CPU/RAM data and LLDP neighbour names of one device; None if it does not speak SNMP."""
    q=lambda o:run(["snmpwalk","-v2c","-c",cm,"-t","1","-r","0","-Oqv",r["ip"],o],8)
    sd=(await q("1.3.6.1.2.1.1.1")).strip()
    if not sd:return None
    n,up,ifd,ino,out,cpu,mt,ma,ll=await asyncio.gather(*[q(o) for o in("1.3.6.1.2.1.1.5","1.3.6.1.2.1.1.3","1.3.6.1.2.1.2.2.1.2","1.3.6.1.2.1.2.2.1.10","1.3.6.1.2.1.2.2.1.16","1.3.6.1.2.1.25.3.3.1.2","1.3.6.1.4.1.2021.4.5","1.3.6.1.4.1.2021.4.6","1.0.8802.1.1.2.1.4.1.1.9")])
    return{"descr":sd[:300],"name":n.strip(),"uptime":up.strip(),"if":ifd.split("\n")[:24],"in":ino.split("\n")[:24],"out":out.split("\n")[:24],"cpu":cpu.split("\n")[:8],"memtotal":mt.strip(),"memavail":ma.strip(),"lldp":[x.strip('" ') for x in ll.split("\n") if x.strip()]}
async def gateway_id():
    r=json.loads(await run(["ip","-j","route","show","default"]) or"[]");gw=r[0].get("gateway") if r else None
    row=db.execute("SELECT id FROM devices WHERE ip=?",(gw,)).fetchone() if gw else None
    return row[0] if row else None
async def snmp_cycle(cm):
    rows=db.execute("SELECT * FROM devices WHERE state!='offline'").fetchall();sem=asyncio.Semaphore(8);now=time.time()
    async def one(r):
        async with sem:
            if SNMPRETRY.get(r["id"],0)>now:return r["id"],None
            o=await snmp_one(r,cm)
            if o is None:SNMPRETRY[r["id"]]=now+600;return r["id"],None  # non-responders are retried every 10 min
            fdb=await collect_fdb(r["ip"],cm)
            if fdb:FDB[r["id"]]=fdb
            return r["id"],o
    llds={}
    for x in await asyncio.gather(*[one(r) for r in rows],return_exceptions=True):
        if isinstance(x,Exception) or x[1] is None:continue
        db.execute("UPDATE devices SET snmp=? WHERE id=?",(json.dumps(x[1]),x[0]));llds[x[0]]=x[1]["lldp"]
    allr=db.execute("SELECT id,hostname,snmp,mac,type FROM devices").fetchall()
    for a,ns in llds.items():  # LLDP neighbour names -> evidence links
        for r in allr:
            nm=[(r["hostname"] or"").split(".")[0].lower(),(json.loads(r["snmp"]).get("name","").split(".")[0] if r["snmp"] else"").lower()]
            if r["id"]!=a and any(n and n.split(".")[0].lower() in nm for n in ns):db.execute("INSERT OR IGNORE INTO links VALUES(?,?)",(min(a,r["id"]),max(a,r["id"])))
    ids={r["id"] for r in allr}
    up=assign_parents([{"id":r["id"],"mac":r["mac"],"type":r["type"]} for r in allr],{k:v for k,v in FDB.items() if k in ids},await gateway_id())
    db.execute("DELETE FROM uplinks");db.executemany("INSERT INTO uplinks VALUES(?,?,?,?)",[(c,p,i,now) for c,(p,i) in up.items()])
    db.commit();await bc({"t":"refresh"})
async def snmp_loop():
    """Background, independent of discovery: a slow SNMP device can never stall host discovery."""
    await asyncio.sleep(20)
    while True:
        try:
            cm=S("snmp_community")
            if cm and active():await snmp_cycle(cm)
        except Exception as e:await ev("warn",f"SNMP error: {e}")
        await asyncio.sleep(60)
TYPES=("mac","nvr","router","firewall","switch","ap","server","nas","windows","linux","printer","camera","tv","iot","phone","unknown","internet")
OSCLASS={"router":"router","broadband router":"router","wap":"ap","wlan accesspoint":"ap","printer":"printer","print server":"printer","switch":"switch","firewall":"firewall","vpn":"firewall","phone":"phone","load balancer":"server","storage-misc":"nas","webcam":"camera","video":"camera","media device":"tv","power-device":"iot"}
def _alias(v):return(str(v or"").strip()[:64]) or None
def _color(v):
    if not v:return None
    if not re.fullmatch(r"#[0-9a-fA-F]{6}",str(v)):raise HTTPException(400,"color must be #RRGGBB")
    return str(v).lower()
def _type(v):
    if v not in TYPES:raise HTTPException(400,"bad type")
    return v
EDITABLE={"alias":_alias,"color":_color,"notes":lambda v:str(v or"")[:4000],"hostname":lambda v:(str(v or"").strip()[:253]) or None,"conn_override":lambda v:v if v in("wifi","lan") else None}
async def enrich(i):
    """Identify one device from everything known + live probes; never overrides user-locked fields."""
    r=db.execute("SELECT * FROM devices WHERE id=?",(i,)).fetchone()
    if not r:return
    ports=[p["port"] for p in json.loads(r["ports"] or"[]")]
    pr=await gather(r["ip"]) if r["state"]!="offline" else Probe()
    f=identify(r["vendor"] or"",r["hostname"] or"",ports,r["os"] or"",pr)
    new={"enriched":time.time()}
    if f.platform:new["platform"]=f.platform
    if f.model:new["model"]=f.model;new["id_src"]=f.source
    if f.name and not r["hostname"]:new["hostname"]=f.name
    if f.os and not r["os"]:new["os"]=f.os
    if not r["type_locked"]:
        t=f.dtype or(r["type"] if r["type"]!="unknown" else classify(r["vendor"] or"",r["hostname"] or"",ports,r["os"] or"",r["ttl"],r["mac"]))
        if r["type"] in("router","switch","ap","firewall") and (not f.dtype or f.dtype in("linux","windows","mac")):t=r["type"]
        new["type"]=t
    cols=list(new)  # keys are constants above, never user input
    db.execute(f"UPDATE devices SET {','.join(c+'=?' for c in cols)} WHERE id=?",[new[c] for c in cols]+[i])
async def enrich_all():
    """New devices at once; devices still without a model are retried every 10 min (phones sleep)."""
    rows=db.execute("SELECT id FROM devices WHERE state!='offline' AND (enriched IS NULL OR (enriched<? AND (model IS NULL OR type='unknown'))) LIMIT 16",(time.time()-600,)).fetchall()
    await asyncio.gather(*[enrich(r["id"]) for r in rows],return_exceptions=True)
async def deep(i):
    """nmap -O -sV: open ports, service versions, OS and the device class nmap reports."""
    r=db.execute("SELECT * FROM devices WHERE id=?",(i,)).fetchone()
    if not r:return
    x=await run(["nmap","-O","-sV","--top-ports","100","-T4","--osscan-guess","-Pn","--max-retries","1","--host-timeout","120s","--script","smb-os-discovery,nbstat","-oX","-",r["ip"]],150)
    try:root=ET.fromstring(x)
    except ET.ParseError:
        db.execute("UPDATE devices SET scanned=? WHERE id=?",(time.time(),i));db.commit();await ev("warn",f"Deep scan failed for {r['ip']} (nmap missing or host blocks probes)",i);return
    ports=[];classes=set()
    for p in root.iter("port"):
        if p.find("state").get("state")!="open":continue
        sv=p.find("service");a=sv.attrib if sv is not None else{}
        if a.get("devicetype"):classes.add(a["devicetype"].lower())
        ports.append({"port":int(p.get("portid")),"proto":p.get("protocol"),"service":a.get("name",""),"version":" ".join(filter(None,[a.get("product"),a.get("version"),a.get("extrainfo")]))})
    om=root.find(".//osmatch")
    if om is not None and int(om.get("accuracy") or 0)<90:om=None  # weak OS guesses are not shown
    os_=om.get("name") if om is not None else None
    oc=om.find("osclass") if om is not None else None
    if oc is not None:classes.add((oc.get("type") or"").lower())
    fam=((oc.get("osfamily") or "").lower() if oc is not None else "");nm_=None
    for s_ in root.iter("script"):
        o=s_.get("output") or ""
        if s_.get("id")=="smb-os-discovery":
            mo=re.search(r"OS: ([^\n(]+)",o);mc=re.search(r"Computer name: (\S+)",o)or re.search(r"FQDN: ([^\s.]+)",o)
            if mo:os_=mo[1].strip();fam="windows"
            if mc:nm_=mc[1]
        elif s_.get("id")=="nbstat" and not nm_:
            mn=re.search(r"NetBIOS name: ([^,\s]+)",o)
            if mn:nm_=mn[1]
    db.execute("UPDATE devices SET ports=?,os=COALESCE(?,os),hostname=COALESCE(hostname,?),scanned=? WHERE id=?",(json.dumps(ports),os_,nm_,time.time(),i))
    ft={"windows":"windows","linux":"linux","mac os x":"mac","macos":"mac"}.get(fam)
    if ft and r["type"] in("unknown",ft) and not r["type_locked"]:db.execute("UPDATE devices SET type=? WHERE id=?",(ft,i))
    dt=next((OSCLASS[c] for c in classes if c in OSCLASS),None)
    if dt and not r["type_locked"]:db.execute("UPDATE devices SET type=? WHERE id=?",(dt,i))
    await enrich(i);db.commit();await ev("scan",f"Deep scan finished for {r['ip']}",i);await bc({"t":"refresh"})
async def deep_loop():
    """Automatic deep scan of every new device, one host at a time (nmap -O is noisy)."""
    await asyncio.sleep(15)
    while True:
        try:
            if S("autoscan")=="1" and active() and not SC["run"]:
                r=db.execute("SELECT id FROM devices WHERE scanned IS NULL AND state='online' ORDER BY first_seen LIMIT 1").fetchone()
                if r:await deep(r["id"])
        except Exception as e:await ev("warn",f"Auto scan error: {e}")
        await asyncio.sleep(5)
import socket,struct,shutil
IFS={};ARPIF={};ARP={};RT={};LASTTICK=[0.0]
class AIf:
    def __init__(s,dev):
        s.dev=dev;i=IFS[dev];s.mac=bytes.fromhex(i["mac"].replace(":",""));s.ip=socket.inet_aton(i["ip"])
        s.k=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0806));s.k.bind((dev,0));s.k.setblocking(False);asyncio.create_task(s.rx())
    async def rx(s):
        l=asyncio.get_running_loop()
        while True:
            try:
                f=await l.sock_recv(s.k,2048)
                if len(f)>=42 and struct.unpack("!H",f[20:22])[0]==2 and f[28:32]!=s.ip:ARP[socket.inet_ntoa(f[28:32])]=(f[22:28].hex(":"),time.time())
            except Exception:await asyncio.sleep(.5)
    def tx(s,ip):s.k.send((b"\xff"*6+s.mac+b"\x08\x06"+struct.pack("!HHBBH6s4s6s4s",1,0x0800,6,4,1,s.mac,s.ip,b"\0"*6,socket.inet_aton(ip))).ljust(60,b"\0"))
async def route(ip):
    if ip not in RT:
        try:j=json.loads(await run(["ip","-j","route","get",ip],2))[0];RT[ip]=(j.get("dev"),not j.get("gateway"))
        except Exception:return None,False
    return RT[ip]
async def arpp(dev,ip,mac):
    try:
        if not IFS.get(dev,{}).get("ip"):return None
        a=ARPIF.get(dev) or ARPIF.setdefault(dev,AIf(dev));t0=time.time();a.tx(ip)
        while time.time()-t0<.9:
            await asyncio.sleep(.03);r=ARP.get(ip)
            if r and r[1]>=t0 and(not mac or r[0]==mac.lower()):return max(.1,(r[1]-t0)*1000)  # MAC must match: proxy-ARP can't fake presence
    except Exception:pass
    return None
async def icmp(ip):
    o=await run(["ping","-n","-c","1","-W","1",ip],3);m=re.search(r"time[=<]([\d.]+)",o);t=re.search(r"ttl=(\d+)",o,re.I)
    return(float(m[1]),int(t[1]) if t else None) if m else None
async def probe(r):
    ip=r["ip"];dev,direct=await route(ip);jobs=[icmp(ip)]
    if direct and dev:jobs.append(arpp(dev,ip,r["mac"]))
    res=await asyncio.gather(*jobs)
    if res[0]:return res[0]
    if len(res)>1 and res[1] is not None:return res[1],None
    if not direct:  # routed only: TCP connect or RST proves the host answered
        for p in(443,80,22,445):
            try:
                t=time.time();_,w=await asyncio.wait_for(asyncio.open_connection(ip,p),.5);w.close();return(time.time()-t)*1000,None
            except ConnectionRefusedError:return 1.0,None
            except Exception:pass
    return None,None
async def monitor():
    sem=asyncio.Semaphore(96);n=0
    async def one(r):
        async with sem:
            try:return r,await asyncio.wait_for(probe(r),4)
            except Exception:return r,(None,None)
    while True:
        if not active():
            await asyncio.sleep(1);continue
        t0=time.time()
        try:
            if n%30==0:await local();RT.clear()
            n+=1;rows=db.execute("SELECT * FROM devices").fetchall();out=[]
            for r,(lat,ttl) in await asyncio.gather(*[one(r) for r in rows]):
                x=st.setdefault(r["id"],{"h":collections.deque(maxlen=10),"f":0});x["h"].append(lat);x["f"]=0 if lat is not None else x["f"]+1
                ls=[v for v in x["h"] if v is not None];loss=100*(len(x["h"])-len(ls))/len(x["h"]);jit=sum(abs(a-b) for a,b in zip(ls,ls[1:]))/(len(ls)-1) if len(ls)>1 else 0
                ns="offline" if x["f"]>=3 else"degraded" if loss>=20 else"online";now=time.time()
                if ns!=r["state"]:
                    db.execute("UPDATE devices SET state=?,state_since=? WHERE id=?",(ns,now,r["id"]));await ev({"offline":"down","degraded":"warn","online":"up"}[ns],f"{r['hostname'] or r['ip']} is now {ns}",r["id"])
                d=dict(r);d.update(jit=jit);c,e=conn(d)
                db.execute("UPDATE devices SET lat=?,jit=?,loss=?,conn=?,evidence=?,ttl=COALESCE(?,ttl),last_seen=CASE WHEN ? THEN ? ELSE last_seen END WHERE id=?",(lat,jit,loss,c,json.dumps(e),ttl,lat is not None,now,r["id"]))
                out.append([r["id"],ns,lat,round(jit,1),round(loss),c,x["f"]])
            db.commit();LASTTICK[0]=time.time();await bc({"t":"tick","ts":LASTTICK[0],"d":out})
        except Exception as e:
            try:await ev("warn",f"Monitor error: {e}")
            except Exception:pass
        await asyncio.sleep(max(0,1-(time.time()-t0)))
async def disc_loop():
    while True:
        if not active():
            await asyncio.sleep(1);continue
        try:await discover()
        except Exception as e:await ev("warn",f"Discovery error: {e}")
        try:await asyncio.wait_for(kick.wait(),int(S("interval")))
        except asyncio.TimeoutError:pass
        kick.clear()
@asynccontextmanager
async def life(a):
    ts=[asyncio.create_task(monitor()),asyncio.create_task(disc_loop()),asyncio.create_task(deep_loop()),asyncio.create_task(snmp_loop()),asyncio.create_task(lldp_listen())];yield
    for t in ts:t.cancel()
app=FastAPI(lifespan=life)
@app.get("/api/devices")
async def devs():return[D(r) for r in db.execute("SELECT * FROM devices ORDER BY ip").fetchall()]
@app.get("/api/events")
async def evs():return list(events)
async def lldpd_read():
    """Neighbors seen by the lldpd daemon (LLDP + CDP/EDP/FDP/SONMP): the switch/port this server is plugged into."""
    x=await run(["lldpctl","-f","json"],8)
    try:j=json.loads(x or"{}")
    except Exception:return
    ifs=(j.get("lldp") or{}).get("interface") or{}
    if isinstance(ifs,list):ifs={k:v for d in ifs for k,v in d.items()}
    for ifn,v in ifs.items():
        ch=v.get("chassis") or{};c=ch if"id" in ch else next(iter(ch.values()),{})
        cid=(c.get("id") or{}).get("value");mg=c.get("mgmt-ip");mg=mg[0] if isinstance(mg,list) else mg
        pt=((v.get("port") or{}).get("id") or{}).get("value")
        if cid or mg:LLDP_SEEN["d_"+ifn]={"chassis":(cid or"").lower(),"mgmt":mg,"port":pt,"ts":time.time()+86400}
async def full_scan():
    """One click = everything: discover, identify, deep-scan every live device, read switch tables. UI shows the result when this ends."""
    if SC["run"]:return
    SC.update(run=1,phase="Şəbəkə axtarılır",done=0,total=0)
    try:
        db.execute("INSERT OR REPLACE INTO settings VALUES('active','1')")  # stays on after restarts
        db.execute("UPDATE devices SET type='unknown',enriched=NULL,scanned=NULL WHERE type_locked=0");db.commit()
        await discover();SC["phase"]="Cihazların vəziyyəti yoxlanılır";await asyncio.sleep(5)
        rows=db.execute("SELECT id FROM devices WHERE state!='offline'").fetchall();SC.update(total=len(rows)+1,done=0,phase="Dərin analiz: OS, port, ad, model")
        sem=asyncio.Semaphore(6)
        async def one(i):
            async with sem:
                try:await deep(i)
                except Exception:pass
                SC["done"]+=1
        await asyncio.gather(*[one(r["id"]) for r in rows])
        SC["phase"]="Bağlantılar öyrənilir (switch/LLDP)";await lldpd_read();cm=S("snmp_community");SNMPRETRY.clear()
        if cm:await snmp_cycle(cm)
        for _ in range(4):await enrich_all()
        SC["done"]=SC["total"]
    except Exception as e:await ev("warn",f"Scan error: {e}")
    finally:SC["run"]=0;db.commit();await bc({"t":"refresh"})
@app.post("/api/scan")
async def scan():
    if not SC["run"]:asyncio.create_task(full_scan())
    return{"ok":1}
@app.get("/api/scan/status")
async def scst():return{**SC,"active":active()}
@app.post("/api/learn")
async def learn():
    """Re-read switch MAC tables (SNMP) right now; physical links exist only where a switch/LLDP proves them."""
    cm=S("snmp_community");SNMPRETRY.clear()
    if cm and active():await snmp_cycle(cm)
    return{"snmp":bool(cm),"links":db.execute("SELECT COUNT(*) FROM uplinks").fetchone()[0],"lldp":db.execute("SELECT COUNT(*) FROM links").fetchone()[0]}
@app.post("/api/devices")
async def add(b:dict):
    ip=str(ipaddress.ip_address(b["ip"]));db.execute("DELETE FROM deleted WHERE k=?",(ip,));now=time.time()
    c=db.execute("INSERT INTO devices(ip,first_seen,last_seen,state_since,manual) VALUES(?,?,?,?,1)",(ip,now,now,now));db.commit();asyncio.create_task(deep(c.lastrowid));return{"id":c.lastrowid}
@app.patch("/api/devices/{i}")
async def patch(i:int,b:dict):
    if b.get("type")=="auto":db.execute("UPDATE devices SET type='unknown',type_locked=0,enriched=NULL WHERE id=?",(i,));kick.set()
    elif "type" in b:db.execute("UPDATE devices SET type=?,type_locked=1 WHERE id=?",(_type(b["type"]),i))
    if "manual_parent" in b:
        v=b["manual_parent"]
        if v in(None,"","auto"):val=None
        elif v=="gw":val=-1
        else:
            try:val=int(v)
            except (TypeError,ValueError):raise HTTPException(400,"bad parent")
            if val==i or not db.execute("SELECT 1 FROM devices WHERE id=?",(val,)).fetchone():raise HTTPException(400,"bad parent")
            x=val
            for _ in range(64):  # a manual chain must never loop back to this device
                row=db.execute("SELECT manual_parent FROM devices WHERE id=?",(x,)).fetchone();x=row[0] if row else None
                if x is None or x<=0:break
                if x==i:raise HTTPException(400,"cycle")
        db.execute("UPDATE devices SET manual_parent=? WHERE id=?",(val,i))
    for k,fn in EDITABLE.items():  # whitelist: column names never come from the request
        if k in b:db.execute(f"UPDATE devices SET {k}=? WHERE id=?",(fn(b[k]),i))
    db.commit();return{"ok":1}
@app.delete("/api/devices/{i}")
async def rm(i:int):
    r=db.execute("SELECT * FROM devices WHERE id=?",(i,)).fetchone()
    if r:db.execute("INSERT OR IGNORE INTO deleted VALUES(?)",(r["mac"] or r["ip"],));db.execute("DELETE FROM devices WHERE id=?",(i,));db.commit()
    return{"ok":1}
@app.post("/api/devices/{i}/deep")
async def dp(i:int):asyncio.create_task(deep(i));return{"ok":1}
@app.post("/api/pos")
async def pos(b:dict):
    npos=json.loads(S("npos"))
    for i,(x,y) in b.items():  # devices keep x/y in their row; hubs, server and internet node in one settings blob
        if str(i).isdigit():db.execute("UPDATE devices SET x=?,y=? WHERE id=?",(x,y,int(i)))
        else:npos[str(i)]=[x,y]
    db.execute("INSERT OR REPLACE INTO settings VALUES('npos',?)",(json.dumps(npos),));db.commit();return{"ok":1}
@app.get("/api/settings")
async def gs():
    s={k:S(k) for k in DEF if k!="npos"};s["snmp_community"]="••••" if s["snmp_community"] else"";return s  # never leaves backend
@app.put("/api/settings")
async def ps(b:dict):
    for k,v in b.items():
        if k in DEF and not(k=="snmp_community" and v=="••••"):db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)",(k,str(v)))
    db.commit();return{"ok":1}
HOP={}
async def next_hop(ip):
    h=HOP.get(ip)
    if h and time.time()-h[0]<60:return h[1]
    r=json.loads(await run(["ip","-j","-4","route","get",ip],3) or"[]");nh=r[0].get("gateway") if r else None
    HOP[ip]=(time.time(),nh);return nh
@app.get("/api/graph")
async def graph():
    """Parent -> child edges built ONLY from evidence. A device's role (type) never influences the wiring.
    Evidence: routing table, LLDP, switch MAC tables (SNMP), manual choice. Everything else sits on its subnet node."""
    nets,own,_=await local()
    r=json.loads(await run(["ip","-j","route","show","default"]) or"[]");gwip=r[0].get("gateway") if r else None
    ds=await devs();by={d["id"]:d for d in ds};byip={d["ip"]:d for d in ds};g=byip.get(gwip);gid=g["id"] if g else None
    def hub_of(ip):
        for t,routed in nets:
            if in_target(ip,t):return(t if"/"in t else t.rpartition(".")[0]+".0/24"),routed
        return ip.rpartition(".")[0]+".0/24",True
    E=[];P={};up={r["child"]:r for r in db.execute("SELECT * FROM uplinks")}
    for d in ds:
        i=d["id"];mp=d.get("manual_parent")
        if i==gid:continue
        if mp==-1 and g:P[i]=(gid,"manual",None)
        elif mp and mp>0 and mp in by and mp!=i:P[i]=(mp,"manual",None)
        elif i in up and up[i]["parent"] in by and up[i]["parent"]!=i:P[i]=(up[i]["parent"],"fdb",up[i]["info"])
    lp=[(a,b) for a,b in db.execute("SELECT a,b FROM links").fetchall() if a in by and b in by]
    def anc(x,y):
        for _ in range(64):
            if x==y:return True
            if x not in P or not isinstance(P[x][0],int):return False
            x=P[x][0]
        return True
    for _ in range(len(lp)+1):  # LLDP is undirected: carry the attachment of one end over to the other
        moved=False
        for a,b in lp:
            for c,p in((b,a),(a,b)):
                if c not in P and c!=gid and(p in P or p==gid) and not anc(p,c):P[c]=(p,"lldp",None);moved=True
        if not moved:break
    for a,b in lp:
        if a not in P and b not in P and gid not in(a,b):P[b]=(a,"lldp",None)
    for i in list(P):  # contradicting evidence must not create loops: cut the loop, the device falls back to its subnet
        x,seen=i,set()
        while x in P and isinstance(P[x][0],int):
            if x in seen:del P[x];break
            seen.add(x);x=P[x][0]
    used={frozenset((c,P[c][0])) for c in P if P[c][1]=="lldp"}
    for a,b in lp:
        if frozenset((a,b)) not in used:E.append({"a":a,"b":b,"solid":1,"src":"lldp","extra":1})
    gl=hub_of(gwip)[0] if gwip else None
    selfip=next((o for o in sorted(own) if hub_of(o)[0]==gl),None) or next(iter(sorted(own)),None)
    top=gid if gid is not None else "self"
    for d in ds:  # no switch/AP/LLDP proof: the only fact is the L3 path, so attach to the real next hop (never to a guessed switch)
        i=d["id"]
        if i==gid or i in P:continue
        loc=any(in_target(d["ip"],t) for t,rt in nets if not rt)
        nh=None if loc else await next_hop(d["ip"]);dv=byip.get(nh) if nh else None
        P[i]=(dv["id"] if dv and dv["id"]!=i else top,"l3",f"via {nh}" if dv else None)
    E+=[{"a":p,"b":c,"solid":1,"src":sr,"info":inf} for c,(p,sr,inf) in P.items()]
    if g:E.append({"a":"inet","b":gid,"solid":1,"src":"route"})
    elif selfip:E.append({"a":"inet","b":"self","solid":1,"src":"route","info":gwip})
    sp=None
    for v in LLDP_SEEN.values():
        dv=next((d for d in ds if d["ip"]==v.get("mgmt") or(v.get("chassis") and d["mac"]==v["chassis"])),None)
        if dv and time.time()-v["ts"]<180:sp=(dv["id"],v.get("port"));break
    if selfip and(sp or top!="self"):E.append({"a":sp[0] if sp else top,"b":"self","solid":1,"src":"lldp" if sp else "l3","info":sp[1] if sp else None})
    return{"edges":E,"gateway":gid,"self":{"ip":selfip} if selfip else None,"npos":json.loads(S("npos")),"hubs":[]}
@app.post("/api/targets/preview")
async def tprev(b:dict):
    t,bad,total,trunc,rng=expand_targets(str(b.get("text",""))[:4000])
    return{"chunks":len(t),"addresses":total,"invalid":bad,"truncated":trunc,"limit":MAX_ADDR,"ranges":rng[:8],"more":max(0,len(rng)-8)}
@app.get("/api/targets/candidates")
async def cands():return{"routes":await route_nets()}
@app.post("/api/targets/probe")
async def tprobe():
    """On click only: ping .1 and .254 (typical gateways) of every /24 inside the server's own private /16."""
    nets,own,_=await local()
    mine=next((o for o in sorted(own) if ipaddress.ip_address(o).is_private),None)
    if not mine:return{"found":[],"error":"Private IP tapılmadı"}
    a,b=mine.split(".")[:2]
    x=await run(["nmap","-sn","-n","-T4","-PE","-PS80,443","-oX","-",f"{a}.{b}.0-255.1,254"],150)
    try:return{"found":alive_nets(x,{n for n,_ in nets}),"probed":f"{a}.{b}.0.0/16"}
    except ET.ParseError:return{"found":[],"error":"nmap cavab vermədi (quraşdırılıb?)"}
STREAMS=[0]
@app.post("/api/console/stream")
async def stream(b:dict):
    """Live ping output; count=0 means until the client disconnects (ping -t). Whitelisted binary, no shell."""
    t=str(b.get("target",""))
    if b.get("cmd")!="ping":raise HTTPException(400,"stream supports ping only")
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}",t):raise HTTPException(400,"bad target")
    try:n=max(0,min(int(b.get("count") or 0),100000))
    except (TypeError,ValueError):raise HTTPException(400,"bad count")
    if STREAMS[0]>=4:raise HTTPException(429,"too many running streams")
    cmd=(["stdbuf","-oL"] if shutil.which("stdbuf") else[])+["ping","-n","-O","-i","1","-W","2"]+(["-c",str(n)] if n else[])+[t]
    async def gen():
        STREAMS[0]+=1;p=None
        try:
            p=await asyncio.create_subprocess_exec(*cmd,stdout=-1,stderr=-2);end=time.time()+3600
            while time.time()<end:
                line=await asyncio.wait_for(p.stdout.readline(),30)
                if not line:break
                yield line
        except OSError:yield b"ping is not available on the server\n"
        except asyncio.TimeoutError:pass
        finally:
            STREAMS[0]-=1
            if p and p.returncode is None:
                try:p.kill()
                except ProcessLookupError:pass
                asyncio.ensure_future(p.wait())  # reap, avoid zombies
    return StreamingResponse(gen(),media_type="text/plain",headers={"Cache-Control":"no-store","X-Accel-Buffering":"no"})
@app.post("/api/console")
async def con(b:dict):
    c,t=b.get("cmd"),str(b.get("target",""))
    if c=="arp":return{"out":await run(["ip","-4","neigh","show"],5)}
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}",t):raise HTTPException(400,"bad target")
    if c=="ping":return{"out":await run(["ping","-n","-c","4","-W","1",t],15)}
    if c=="dns":
        def lk():
            try:return socket.gethostbyaddr(t)[0] if re.fullmatch(r"[\d.]+",t) else"\n".join(socket.gethostbyname_ex(t)[2])
            except Exception as e:return f"lookup failed: {e}"
        return{"out":await asyncio.to_thread(lk)}
    if c=="ports":
        try:
            if not ipaddress.ip_address(t).is_private:raise ValueError
        except ValueError:raise HTTPException(400,"ports: private IPs only")
        return{"out":await run(["nmap","-Pn","-T4","--top-ports","100",t],120)}
    raise HTTPException(400,"allowed: ping, ports, dns, arp")
@app.get("/api/health")
async def health():
    return{"tick":LASTTICK[0],"now":time.time(),"devices":db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],"ws":len(clients),"arp":list(ARPIF),"tools":{t:bool(shutil.which(t)) for t in("nmap","ping","snmpwalk","ip")}}
@app.websocket("/ws")
async def ws(w:WebSocket):
    await w.accept();clients.add(w)
    try:
        while True:await w.receive_text()
    except WebSocketDisconnect:clients.discard(w)
@app.get("/")
async def idx():return FileResponse(B+"/static/index.html")
app.mount("/static",StaticFiles(directory=B+"/static"),name="s")
if __name__=="__main__":uvicorn.run(app,host="0.0.0.0",port=int(os.environ.get("NETMAP_PORT","80")),log_level="warning")
