#!/usr/bin/env python

import sys
from scapy.all import *

flag = []

pcapfile ="/home/kali/Desktop/ITP4415/Assign/nmap/nmap-sS&sT.pcap"

print(f"[+] Reading: {pcapfile}")
scapy_pcap = rdpcap(pcapfile)
numofpkts = len(scapy_pcap)
print(f"[+] NUmber of packets {numofpkts}")

i = 1

host_ip = "192.168.186.155"
target_ip = "192.168.186.156"

target_ports=[21,22,23,80]

#for target_port in target_ports:

for pkt in scapy_pcap:

    try:
        #p_all = pkt.mysummary
        #print(p_all)
        #print("\n--------------")
		
        p_dstIP = pkt["IP"].dst
        p_srcIP = pkt["IP"].src
        if ((str(p_dstIP) == host_ip or str(p_dstIP) == target_ip) and (str(p_srcIP) == host_ip or str(p_srcIP) == target_ip)):
            flag.append(str(pkt["TCP"].flags))
            #flag.append(str(pkt["TCP"].flags))
            """
            print (str(i))
            print(f"dst IP: {p_dstIP}")
            print(f"src IP: {p_srcIP}")
            if pkt["IP"].sport == target_port or pkt["IP"].dport == target_port:
                if pkt["IP"].dport == target_port:
                    flag.append(str(pkt["TCP"].flags))
                elif pkt["IP"].sport == target_port:
                    flag.append(str(pkt["TCP"].flags))
            print("\n--------------")"""
            print(f"Pattern: {flag}")
            if ((flag[0] == "S" and flag[1] == "SA" and flag[2] == "A" and flag[3] == "RA") or (flag[0] == "S" and flag[1] == "SA" and flag[2] == "R")):
                if flag[0] == "S" and flag[1] == "SA" and flag[2] == "A" and flag[3] == "RA":
                    print(f"dst IP: {p_dstIP}")
                    print(f"src IP: {p_srcIP}")
                    print(f"Pattern: {flag}")
                    print(f"This is Nmap -sT and port {target_port}")
                    print("\n--------------")
                if flag[0] == "S" and flag[1] == "SA" and flag[2] == "R":
                    print(f"dst IP: {p_dstIP}")
                    print(f"src IP: {p_srcIP}")
                    print(f"Pattern: {flag}")
                    print(f"This is Nmap -sS and port {target_port}")
                    print("\n--------------")
                flag.clear()
    except:
        pass
	#print("\n====================================\n")
    i = i+1
