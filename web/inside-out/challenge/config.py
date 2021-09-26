from dotenv import load_dotenv
import os
import socket
import ipaddress
import netifaces

load_dotenv()

LOG_FILE = os.getenv("LOG_FILE")
FLAG = os.getenv("FLAG")

# Local IP
# https://stackoverflow.com/a/28950776
# def get_ip():
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         # doesn't even have to be reachable
#         s.connect(('10.255.255.255', 1))
#         IP = s.getsockname()[0]
#     except Exception:
#         IP = '127.0.0.1'
#     finally:
#         s.close()
#     return IP

# ASSUMED ADAPTER is eth0
addr_info = netifaces.ifaddresses("eth0")[netifaces.AF_INET][0]
cidr_bits = ipaddress.IPv4Network(f"0.0.0.0/{addr_info['netmask']}").prefixlen
LOCAL_CIDR = addr_info["addr"] + "/" + str(cidr_bits)

# print(LOCAL_CIDR)
