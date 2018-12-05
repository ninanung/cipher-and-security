from socket import *
import os
import struct

def parseHeader(data):
    header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    return header

def getDatagramSize(header):
    return header[2]

def getProtocol(header):
    proto = header[6]
    if proto is 1:
        return 'ICMP'
    elif proto is 6:
        return 'TCP'
    elif proto is 17: 
        return 'UDP'

def getIPs(header):
    src = inet_ntoa(header[8])
    dest = inet_ntoa(header[9])
    return (src, dest)

def getIPHeaderLen(header):
    headerlen = header[0] & 0X0F
    headerlen *= 4
    return headerlen

def getTypeCode(icmp):
    icmpheader = struct.unpack('!BB', icmp[:2])
    icmpType = icmpheader[0]
    icmpCode = icmpheader[1]
    return (icmpType, icmpCode)

def recvData(sock):
    data = ''
    try:
        data = sock.recvfrom(65565)
    except timeout:
        data = ''
    return data[0]

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

    count = 1
    try:
        while True:
            data = recvData(sniffer)
            print(str(count) + ' sniffed time')
            header = parseHeader(data[:20])
            headerlen = getIPHeaderLen(header)
            print('datagram size = %s' %str(getDatagramSize(header)))
            print('protocol = %s' %getProtocol(header))
            src, dest = getIPs(header)
            print('source ip = %s' %src)
            print('destination ip = %s' %dest)
            if getProtocol(header) is 'ICMP':
                offset = headerlen
                icmpType, icmpCode = getTypeCode(data[offset:])
                print('%s -> %s | type: %d | code: %d' %(src, dest, icmpType, icmpCode))
            print('--------------------------------------------')
            count += 1
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)

def main():
    host = gethostbyname(gethostname())
    print("sniffing : " + host)
    sniffing(host)

if __name__ == "__main__":
    main()