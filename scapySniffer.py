from scapy.all import *

protocols = {1:'ICMP', 6:'TDP', 17:'UDP'}

def showPacket(packet):
    srcip = packet[0][1].src
    dstip = packet[0][1].dst
    proto = packet[0][1].proto
    if proto in protocols:
        print('protocol: %s, %s -> %s' %(proto, srcip, dstip))
        if proto == 1:
            print('type: %d, code: %d' %(packet[0][2].type, packet[0][2].code))

def main():
    sniff(filter='ip', prn=showPacket, count=0)

if __name__ == '__main__':
    main()