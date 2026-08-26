import ipaddress, socket

def ip_info(value):
    try:
        ip = ipaddress.ip_address(value)
        return {"input": value, "version": ip.version, "private": ip.is_private, "global": ip.is_global, "loopback": ip.is_loopback, "link_local": ip.is_link_local, "multicast": ip.is_multicast}
    except ValueError:
        return {"input": value, "resolved": sorted({x[4][0] for x in socket.getaddrinfo(value, None)})}

def dns_info(host):
    return sorted({x[4][0] for x in socket.getaddrinfo(host, None)})
