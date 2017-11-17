import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

ip = input("IP: ")

def packetgen(s):
    h = "".join(["{:02x}".format(ord(c)) for c in s])
    h = [h[i:i+2] for i in range(0,len(h),2)]
    h = [h[i:i+6] for i in range(0,len(h),6)]  
    h[-1].extend(['20'] * (6 - len(h[-1])))
    macs = [":".join(a) for a in h]
    return ARP(hwsrc=macs, pdst=ip, psrc='192.168.178.188')

exit = False    

while not exit:
    ui = input("payload: ")
    if ui == 'exit':
        exit = True
    else:
        send(packetgen(ui))
        send(ARP(hwsrc="ee:ee:ee:ee:ee:ee", pdst=ip, psrc='192.168.178.188'), count=3)

