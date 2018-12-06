from scapy.all import *

def showPacket(packet):
    print(packet.show())

def main():
    sniff(filter='ip', prn=showPacket, count=1)

if __name__ == '__main__':
    main()