import ipaddress, platform, re, shutil, socket, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def info():
    hostname = socket.gethostname()
    addrs = sorted({x[4][0] for x in socket.getaddrinfo(hostname, None) if ':' not in x[4][0]})
    return {"hostname": hostname, "addresses": addrs}

def _default_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local = s.getsockname()[0]
    finally:
        s.close()
    # Conservative common-LAN inference when OS route APIs are unavailable.
    parts = local.split('.')
    network = ipaddress.ip_network(local + '/24', strict=False)
    return local, str(network)

def _ping(ip):
    system = platform.system()
    cmd = ["ping", "-n", "1", "-w", "700", ip] if system == "Windows" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        text = p.stdout + p.stderr
        m = re.search(r'(?:time[=<]\s*)([0-9.]+)\s*ms', text, re.I)
        return (p.returncode == 0, float(m.group(1)) if m else None)
    except Exception:
        return False, None

def _reverse(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return None

def _arp_table():
    try:
        cmd = ["arp", "-a"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        table = {}
        for line in p.stdout.splitlines():
            m = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})', line)
            if m: table[m.group(1)] = m.group(2)
        return table
    except Exception:
        return {}

def discover(subnet=None, max_hosts=1024):
    local, inferred = _default_subnet()
    subnet = subnet or inferred
    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses > max_hosts:
        raise ValueError("Subnet is too large for the default discovery limit; specify a smaller authorised subnet.")
    arp = _arp_table()
    targets = [str(x) for x in net.hosts()]
    results = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_ping, ip): ip for ip in targets}
        for f in as_completed(futures):
            ip = futures[f]
            online, latency = f.result()
            if online or ip in arp:
                results.append({"ip": ip, "status": "ONLINE" if online else "SEEN_ARP", "latency_ms": latency, "mac": arp.get(ip), "hostname": _reverse(ip), "this_device": ip == local})
    results.sort(key=lambda x: tuple(int(v) for v in x["ip"].split('.')))
    return {"local_ip": local, "subnet": str(net), "devices": results}

def nmap_discover(target):
    if shutil.which("nmap") is None:
        raise RuntimeError("Nmap is not installed or is not in PATH.")
    p = subprocess.run(["nmap", "-sn", target], capture_output=True, text=True, timeout=180)
    return (p.stdout + "\n" + p.stderr).strip()
