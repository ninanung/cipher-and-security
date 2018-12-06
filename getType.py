from socket import *
import struct
import os

def parseHeader(data):
    header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    return header

def getIPs(header):
    src = inet_ntoa(header[8])
    return src

def getTypeCode(icmp):
    icmpheader = struct.unpack('!BB', icmp[:2])
    icmpType = icmpheader[0]
    icmpCode = icmpheader[1]
    return (icmpType, icmpCode)

def getProtocol(header):
    proto = header[6]
    if proto is 1:
        return 'ICMP'
    elif proto is 6:
        return 'TCP'
    elif proto is 17: 
        return 'UDP'
 
def recvData(sock):
    data = ''
    try:
        data = sock.recvfrom(65565)
    except timeout:
        data = ''
    return data[0]

def getIPHeaderLen(header):
    headerlen = header[0] & 0X0F
    headerlen *= 4
    return headerlen

def sniffing(host):
    if os.name == 'nt':
        sock_protocol = IPPROTO_IP
    else:
        sock_protocol = IPPROTO_ICMP
    sniffer = socket(AF_INET, SOCK_RAW, sock_protocol)
    sniffer.bind((host, 1))
    sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    if os.name == 'nt':
        sniffer.ioctl(SIO_RCVALL, RCVALL_ON)
    try:
        while True:
            data = recvData(sniffer)
            header = parseHeader(data[:20])
            headerlen = getIPHeaderLen(header)
            src = getIPs(header)
            if getProtocol(header) is 'ICMP':
                offset = headerlen
                icmpType, icmpCode = getTypeCode(data[offset:])
                if icmpType is 0:
                    print('%s, im alive!' %src)
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)

def main():
    host = gethostbyname(gethostname())
    print('%s sniffing' %host)
    sniffing(host)

if __name__ == '__main__':
    main()