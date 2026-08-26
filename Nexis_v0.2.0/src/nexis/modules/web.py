from urllib.request import Request, urlopen
HEADERS=["Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","Referrer-Policy","Permissions-Policy"]
def headers(url):
    if not url.startswith(("http://","https://")): url="https://"+url
    with urlopen(Request(url,headers={"User-Agent":"Nexis/0.2.0"}),timeout=15) as r:
        h=dict(r.headers.items())
        return {"url":r.geturl(),"status":r.status,"security_headers":{x:h.get(x) for x in HEADERS}}
