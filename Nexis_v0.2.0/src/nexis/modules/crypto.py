import base64, hashlib, re
from pathlib import Path

def identify(value):
    value=value.strip(); result=[]
    for pattern,name in [(r"^[0-9a-fA-F]{32}$","MD5-shaped digest"),(r"^[0-9a-fA-F]{40}$","SHA-1-shaped digest"),(r"^[0-9a-fA-F]{64}$","SHA-256-shaped digest"),(r"^[0-9a-fA-F]{96}$","SHA-384-shaped digest"),(r"^[0-9a-fA-F]{128}$","SHA-512-shaped digest")]:
        if re.fullmatch(pattern,value): result.append(name)
    for prefix,name in {"$2a$":"bcrypt","$2b$":"bcrypt","$2y$":"bcrypt","$argon2id$":"Argon2id","$argon2i$":"Argon2i","$5$":"Unix SHA-256 crypt","$6$":"Unix SHA-512 crypt","eyJ":"Possibly a JWT"}.items():
        if value.startswith(prefix): result.append(name)
    if value.startswith("$") and value.count("$")>=2: result.append("Modular Crypt Format style")
    if len(value)%4==0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}",value):
        try: base64.b64decode(value,validate=True); result.append("Valid standard Base64 encoding")
        except Exception: pass
    return list(dict.fromkeys(result))

def file_hash(path, algorithms=None):
    path=Path(path).expanduser().resolve()
    if not path.is_file(): raise FileNotFoundError(path)
    out={}
    for alg in algorithms or ["sha256"]:
        alg=alg.lower()
        if alg not in {x.lower() for x in hashlib.algorithms_available}: raise ValueError(f"Unsupported hash algorithm: {alg}")
        h=hashlib.new(alg)
        with path.open("rb") as f:
            for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
        out[alg]=h.hexdigest()
    return out
