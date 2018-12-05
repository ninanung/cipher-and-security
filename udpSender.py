from socket import *
from netaddr import IPNetwork, IPAddress

def sendMsg(subnet, msg):
    sock = socket(AF_INET, SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        try:
            print('sending msg to %s' %ip)
            sock.sendto(msg.encode('utf-8'), ('%s' %ip, 9000))
        except Exception as e:
            print(e)

def main():
    host = gethostbyname(gethostname())
    subnet = host + '/24'
    msg = '뚱인데요'
    sendMsg(subnet, msg)

if __name__ == '__main__':
    main()