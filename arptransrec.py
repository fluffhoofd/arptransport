import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

code = ""

def message():
    msg = [code[i:i+2] for i in range(0,len(code),2)]
    msgd = [chr(int(i,16)) for i in msg]
    print("".join(msgd).strip())

def pcall(x):
    global code
    if ARP in x:
        if x[ARP].psrc == '192.168.178.188':
            d = x[ARP].hwsrc.replace(":","")
            if d == "eeeeeeeeeeee":
                message()
                code = ""
            else:
               code += d

sniff(prn=pcall)
