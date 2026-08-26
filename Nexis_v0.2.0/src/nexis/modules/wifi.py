import platform, subprocess

def info():
    system = platform.system()
    if system == "Windows": cmd = ["netsh", "wlan", "show", "interfaces"]
    elif system == "Linux": cmd = ["bash", "-lc", "iw dev"]
    else: return f"Wi-Fi information is not implemented for {system} yet."
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (p.stdout + "\n" + p.stderr).strip()
    except Exception as e: return f"Wi-Fi information unavailable: {e}"
