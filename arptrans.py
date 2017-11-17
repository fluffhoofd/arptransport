from scapy.all import *

ip = input("IP: ")
s = input("payload: ")

h = "".join(["{:02x}".format(ord(c)) for c in s])
h = [h[i:i+2] for i in range(0,len(h),2)]
h = [h[i:i+6] for i in range(0,len(h),6)]  
h[-1].extend(['65'] * (6 - len(h[-1])))
macs = [":".join(a) for a in h]
print(macs)

send(ARP(hwsrc=macs, psrc=ip), inter=1)
send(ARP(hwsrc="eeeeeeeeeeee", psrc=ip), count=3)
