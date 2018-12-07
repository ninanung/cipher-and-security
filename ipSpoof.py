from scapy.all import *

def ipSpoof(srcip, dstip):
    ipPacket = IP(src=srcip, dst=dstip) / ICMP()
    print(ipPacket.show())
    send(ipPacket)

def main():
    srcip = '192.168.1.144'
    dstip = '216.58.197.142'
    try:
        while True:
            ipSpoof(srcip, dstip)
    except KeyboardInterrupt:
        print('ping stopped')
    print('sent spoofed ip %s -> %s' %(srcip, dstip))

if __name__ == '__main__':
    main()