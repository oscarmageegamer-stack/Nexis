from __future__ import annotations

import cmd
import json
import shlex
import sys
import time
from pathlib import Path

from . import __version__
from .core.baseline import compare_devices, establish
from .core.risk import assess_network_change
from .core.store import load_baseline, recent_events, record_event
from .modules import crypto, host, network, recon, web, wifi

C = "\033[96m"
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
Z = "\033[0m"


def colour(text: str, code: str) -> str:
    return f"{code}{text}{Z}" if sys.stdout.isatty() else text


def banner() -> None:
    print(colour("""
███╗   ██╗███████╗██╗  ██╗██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝
""", C))
    print(f"  Nexis v{__version__} — Security Intelligence Framework\n")


class Console(cmd.Cmd):
    prompt = colour("Nexis > ", C)

    def do_help(self, arg):
        print("""Commands
--------
help
modules
version
clear
exit / quit

Recon
  recon ip <address-or-host>
  recon dns <hostname>

Network
  network info
  network discover [subnet]
  network baseline
  network changes [subnet]
  network investigate <ip>
  network nmap <authorised-target>

Wi-Fi
  wifi info

Crypto
  crypto identify <hash-or-string>
  crypto hash <file> [sha256 sha512 ...]

Web / Host
  web headers <authorised-url>
  host info

Intelligence
  events [count]
  report
  watch network [seconds]
""")

    def do_modules(self, arg):
        print("""RECON       IP and DNS information
NETWORK     Discovery, baseline and Nmap
WIFI        Local Wi-Fi information
CRYPTO      Hash identification + file hashing
WEB         HTTP security-header inspection
HOST        Local host information
INTELLIGENCE Baseline, events, correlation and monitoring
REPORT      Session JSON output""")

    def do_version(self, arg):
        print(f"Nexis v{__version__}")

    def do_clear(self, arg):
        print("\033[2J\033[H", end="")

    def do_recon(self, arg):
        p = shlex.split(arg)
        try:
            if len(p) == 2 and p[0].lower() == "ip":
                print(json.dumps(recon.ip_info(p[1]), indent=2))
            elif len(p) == 2 and p[0].lower() == "dns":
                print(json.dumps({"hostname": p[1], "addresses": recon.dns_info(p[1])}, indent=2))
            else:
                print(colour("[!] Usage: recon ip <value> | recon dns <hostname>", R))
        except Exception as exc:
            print(colour(f"[!] {exc}", R))

    def _discover(self, subnet=None):
        snapshot = network.discover(subnet)
        record_event("network_snapshot", {"subnet": snapshot["subnet"], "device_count": len(snapshot["devices"])})
        return snapshot

    def _print_devices(self, snapshot):
        print(f"Local IP: {snapshot['local_ip']}")
        print(f"Subnet:   {snapshot['subnet']}\n")
        print(f"{'IP':<18}{'STATUS':<12}{'LATENCY':<12}{'HOSTNAME':<32}")
        print("-" * 74)
        for device in snapshot["devices"]:
            latency = "-" if device.get("latency_ms") is None else f"{device['latency_ms']:.1f} ms"
            name = device.get("hostname") or "unknown"
            if device.get("this_device"):
                status = "THIS PC"
            else:
                status = device.get("status", "ONLINE")
            print(f"{device['ip']:<18}{status:<12}{latency:<12}{name[:31]:<32}")
        print(f"\n{len(snapshot['devices'])} device(s) observed")

    def do_network(self, arg):
        p = shlex.split(arg)
        try:
            if p == ["info"]:
                print(json.dumps(network.info(), indent=2))
            elif p and p[0].lower() == "discover":
                snapshot = self._discover(p[1] if len(p) > 1 else None)
                self._print_devices(snapshot)
            elif p == ["baseline"]:
                snapshot = self._discover()
                establish(snapshot)
                print(colour("[+] Baseline established.", G))
            elif p and p[0].lower() == "changes":
                snapshot = self._discover(p[1] if len(p) > 1 else None)
                delta = compare_devices(load_baseline(), snapshot)
                assessment = assess_network_change(delta)
                print(json.dumps({"changes": delta, "assessment": assessment}, indent=2))
            elif len(p) == 2 and p[0].lower() == "investigate":
                ip = p[1]
                snapshot = self._discover()
                device = next((d for d in snapshot["devices"] if d["ip"] == ip), None)
                if not device:
                    print(colour("[?] Device not observed on the current local discovery.", Y))
                    return
                print(json.dumps({
                    "target": device,
                    "scope": "local-network-observation",
                    "assessment": "Observation only; no compromise is inferred."
                }, indent=2))
            elif len(p) == 2 and p[0].lower() == "nmap":
                print(network.nmap_discover(p[1]))
            else:
                print(colour("[!] Usage: network info | discover [subnet] | baseline | changes [subnet] | investigate <ip> | nmap <target>", R))
        except Exception as exc:
            print(colour(f"[!] {exc}", R))

    def do_wifi(self, arg):
        if arg.strip().lower() == "info":
            print(wifi.info())
        else:
            print(colour("[!] Usage: wifi info", R))

    def do_crypto(self, arg):
        p = shlex.split(arg)
        try:
            if len(p) >= 2 and p[0].lower() == "identify":
                results = crypto.identify(p[1])
                if results:
                    print(colour("[+] Likely formats:", G))
                    for result in results:
                        print(f"  • {result}")
                else:
                    print(colour("[?] No confident match.", Y))
            elif len(p) >= 2 and p[0].lower() == "hash":
                for algorithm, digest in crypto.file_hash(p[1], p[2:] or ["sha256"]).items():
                    print(f"{algorithm.upper():>10}: {digest}")
            else:
                print(colour("[!] Invalid crypto command.", R))
        except Exception as exc:
            print(colour(f"[!] {exc}", R))

    def do_web(self, arg):
        p = shlex.split(arg)
        if len(p) == 2 and p[0].lower() == "headers":
            try:
                print(json.dumps(web.headers(p[1]), indent=2))
            except Exception as exc:
                print(colour(f"[!] {exc}", R))
        else:
            print(colour("[!] Usage: web headers <authorised-url>", R))

    def do_host(self, arg):
        if arg.strip().lower() == "info":
            print(json.dumps(host.info(), indent=2))
        else:
            print(colour("[!] Usage: host info", R))

    def do_events(self, arg):
        p = shlex.split(arg)
        limit = 20
        if p:
            try:
                limit = max(1, min(200, int(p[0])))
            except ValueError:
                print(colour("[!] events [count]", R))
                return
        events = recent_events(limit)
        if not events:
            print("No events recorded.")
            return
        for event in events:
            print(json.dumps(event, separators=(",", ":")))

    def do_watch(self, arg):
        p = shlex.split(arg)
        if not p or p[0].lower() != "network":
            print(colour("[!] Usage: watch network [seconds]", R))
            return
        interval = 30
        if len(p) > 1:
            try:
                interval = max(5, int(p[1]))
            except ValueError:
                print(colour("[!] Interval must be an integer number of seconds.", R))
                return
        print(colour("[+] Network watch started. Press Ctrl+C to stop.", G))
        previous = load_baseline()
        try:
            while True:
                snapshot = self._discover()
                delta = compare_devices(previous, snapshot)
                assessment = assess_network_change(delta)
                if any(delta.values()):
                    print(colour("\n[!] Network baseline change detected", Y))
                    print(json.dumps({"changes": delta, "assessment": assessment}, indent=2))
                previous = snapshot
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[+] Network watch stopped.")

    def do_report(self, arg):
        out = Path("reports")
        out.mkdir(exist_ok=True)
        file = out / "nexis_session.json"
        payload = {"tool": "Nexis", "version": __version__, "events": recent_events(200)}
        file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(colour(f"[+] Report written to {file.resolve()}", G))

    def do_exit(self, arg):
        print("Nexis shutting down.")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def default(self, line):
        value = line.strip()
        if not value:
            return
        results = crypto.identify(value)
        if results:
            print(colour("[+] This looks like:", G))
            for result in results:
                print(f"  • {result}")
        else:
            print(colour("[?] Unknown command. Type 'help'.", Y))


def main():
    banner()
    try:
        Console().cmdloop()
    except KeyboardInterrupt:
        print("\nNexis shutting down.")
