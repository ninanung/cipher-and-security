from scapy.all import *

def showPacket(packet):
    data = '%s' %(packet[0][2].payload)
    #if 'user' in data.lower() or 'pass' in data.lower():
    print('%s : %s' %(packet[0][1].dst, data))

def main(filter):
    print('start sniffing')
    sniff(filter=filter, prn=showPacket, count=0, store=0)

if __name__ == '__main__':
    filter = 'ip'#'tcp port 25 or tcp port 110 or tcp port 143 or tcp port 465 or tcp port 995'
    main(filter)