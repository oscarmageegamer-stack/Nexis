import os, platform, socket
def info(): return {"hostname":socket.gethostname(),"platform":platform.platform(),"system":platform.system(),"release":platform.release(),"machine":platform.machine(),"cpu_count":os.cpu_count()}
