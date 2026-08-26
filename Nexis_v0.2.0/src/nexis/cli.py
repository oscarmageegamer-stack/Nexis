import cmd,json,shlex,sys
from pathlib import Path
from . import __version__
from .modules import recon,network,wifi,crypto,web,host
C="\033[96m";G="\033[92m";Y="\033[93m";R="\033[91m";Z="\033[0m"
def col(s,c): return f"{c}{s}{Z}" if sys.stdout.isatty() else s
def banner(): print(col("N E X I S",C)+f"  v{__version__} — Ethical Security Framework\n")
class Console(cmd.Cmd):
    prompt=col("Nexis > ",C)
    def do_help(self,a): print("""Commands\n--------\nhelp\nmodules\nversion\nclear\nexit / quit\n\nrecon ip <address-or-host>\nrecon dns <hostname>\n\nnetwork info\nnetwork discover [subnet]\nnetwork nmap <authorised-target>\n\nwifi info\n\ncrypto identify <hash-or-string>\ncrypto hash <file> [sha256 sha512 ...]\n\nweb headers <authorised-url>\nhost info\nreport\n""")
    def do_modules(self,a): print("RECON   IP/DNS\nNETWORK Local discovery + Nmap\nWIFI    Local adapter info\nCRYPTO  Hash identification + file hashing\nWEB     Security headers\nHOST    Local host info\nREPORT  JSON")
    def do_version(self,a): print(f"Nexis v{__version__}")
    def do_clear(self,a): print("\033[2J\033[H",end="")
    def do_recon(self,a):
        p=shlex.split(a)
        try:
            if len(p)==2 and p[0]=="ip": print(json.dumps(recon.ip_info(p[1]),indent=2))
            elif len(p)==2 and p[0]=="dns": print(json.dumps({"hostname":p[1],"addresses":recon.dns_info(p[1])},indent=2))
            else: print(col("[!] Usage: recon ip <value> | recon dns <hostname>",R))
        except Exception as e: print(col(f"[!] {e}",R))
    def do_network(self,a):
        p=shlex.split(a)
        try:
            if p==["info"]: print(json.dumps(network.info(),indent=2))
            elif p and p[0]=="discover":
                r=network.discover(p[1] if len(p)>1 else None); print(json.dumps(r,indent=2));
            elif len(p)==2 and p[0]=="nmap": print(network.nmap_discover(p[1]))
            else: print(col("[!] Usage: network info | network discover [subnet] | network nmap <target>",R))
        except Exception as e: print(col(f"[!] {e}",R))
    def do_wifi(self,a): print(wifi.info() if a.strip()=="info" else col("[!] Usage: wifi info",R))
    def do_crypto(self,a):
        p=shlex.split(a)
        try:
            if len(p)>=2 and p[0]=="identify":
                r=crypto.identify(p[1]); print(col("[+] Likely formats:",G)); [print("  • "+x) for x in r] if r else print(col("[?] No confident match.",Y))
            elif len(p)>=2 and p[0]=="hash":
                for k,v in crypto.file_hash(p[1],p[2:] or ["sha256"]).items(): print(f"{k.upper():>10}: {v}")
            else: print(col("[!] Invalid crypto command.",R))
        except Exception as e: print(col(f"[!] {e}",R))
    def do_web(self,a):
        p=shlex.split(a)
        try: print(json.dumps(web.headers(p[1]),indent=2)) if len(p)==2 and p[0]=="headers" else print(col("[!] Usage: web headers <authorised-url>",R))
        except Exception as e: print(col(f"[!] {e}",R))
    def do_host(self,a): print(json.dumps(host.info(),indent=2) if a.strip()=="info" else col("[!] Usage: host info",R))
    def do_report(self,a):
        Path("reports").mkdir(exist_ok=True); f=Path("reports/nexis_session.json"); f.write_text(json.dumps({"tool":"Nexis","version":__version__},indent=2)); print(col(f"[+] Report written to {f.resolve()}",G))
    def do_exit(self,a): print("Nexis shutting down."); return True
    def do_quit(self,a): return self.do_exit(a)
def main(): banner(); Console().cmdloop()
