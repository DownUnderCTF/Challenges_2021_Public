import socket
import re
import ipaddress
import random

def is_localhost(target):
    result = False
    #  IPv4
    try:
        ip = ipaddress.IPv4Address(socket.gethostbyname(target))
        if ip.is_loopback:
            result = True
    except:
        pass

    # IPv6
    try:
        ip = ipaddress.IPv6Address(socket.gethostbyname(socket.getaddrinfo(target, None, socket.AF_INET6)[0][4][0]))
        if ip.is_loopback:
            result = True
    except:
        pass

    # Test 0.0.0.0 bypass

    return result

def get_title(html):
    title = ""
    try:
        find_title = re.search('<\W*title\W*(.*)</title', html, re.IGNORECASE)
        title = find_title.group(1)
    except:
        # Yes I am evil hehe
        pass

    return title

def generate_random_ip():
    return f"{random.randint(256,999)}.{random.randint(256,999)}.{random.randint(256,999)}.{random.randint(256,999)}"
