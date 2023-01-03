import logging
#set up logger
logging.getLogger("scapy.runtime").setLevel(logging.error)
import sys
from scapy.all import sr,sr1, IP, TCP 

if len(sys.argv) != 4: # -> throws error if there are no 4 arguments on stdin => python3 ScapyPortscanner.py IP_ADDR PORTS
    print("Usage: %s target startpoint endport" %(sys.argv[0]))
    sys.exit(0)

target = str(sys.argv[1]) #second argument stdin
startport = int(sys.argv[2])
endport = int(sys.argv[3])
print("Scanning" + " " + target + " for open TCP ports\n")

if startport == endport:
    endport+=1

for x in range(startport, endport):
    packet = IP(dst=target)/TCP(dport=x,flag="s")
    response = sr1(packet, timeout=0.5, verbose=0)
    if response.haslayer(TCP) and response.getlayer(TCP).flag == 0x12: #SYN-ACK Flag
        print("PORT" + str(x) + " is open!")
    sr(IP(dst=target)/TCP(dport=response.sport, flag="r"), timeout = 0.5, verbose = 0)

print("Scan is complete!\n")


