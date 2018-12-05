from socket import *
import os
import struct

def parse_ipheader(data):
	ipheader = struct.unpack('!BBHHHBBH4s4s' , data[:20])
	return ipheader
	
def getProtocol(ipheader):
	protocols = {1:'ICMP', 6:'TCP', 17:'UDP'}
	proto = ipheader[6]
	if proto in protocols:
		return protocols[proto]
	else:
		return 'OHTERS'
		
def getIP(ipheader):
	src_ip = inet_ntoa(ipheader[8])
	dest_ip = inet_ntoa(ipheader[9])
	return (src_ip, dest_ip)

def getIPHeaderLen(ipheader):
	ipheaderlen = ipheader[0] & 0x0F
	ipheaderlen *= 4
	return ipheaderlen	
	
def getTypeCode(icmp):
	icmpheader = struct.unpack('!BB' , icmp[:2])
	icmp_type = icmpheader[0]
	icmp_code = icmpheader[1]
	return (icmp_type, icmp_code)
	
def recvData(sock):
	data = ''
	try:
		data = sock.recvfrom(65565)
	except timeout:
		data = ''
		
	return data[0]
	

def sniffing(host):
	# Create a raw socket and bind it to the public interface
	if os.name == 'nt':
		sock_protocol = IPPROTO_IP
	else:
		sock_protocol = IPPROTO_ICMP
		
	sniffer = socket(AF_INET, SOCK_RAW, sock_protocol)
	sniffer.bind((host, 0))
	
	# Want the IP headers included in the capture
	sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
	
	# if we're using Windows, we need to send an IOCTL to setup promiscuous mode
	if os.name == 'nt':
		sniffer.ioctl(SIO_RCVALL, RCVALL_ON)	
		
	try:
		while True:
			data = recvData(sniffer)
			ipheader = parse_ipheader(data[:20])
			ipheaderlen = getIPHeaderLen(ipheader)			
			protocol = getProtocol(ipheader)
			src_ip, dest_ip = getIP(ipheader)			
			if protocol == 'ICMP':				
				offset = ipheaderlen
				icmp_type, icmp_code = getTypeCode(data[offset:])
				print('%s -> %s: ICMP: Type[%d], Code[%d]' %(src_ip, dest_ip, icmp_type, icmp_code))
	
	except KeyboardInterrupt:  # Ctrl-C key input
		if os.name == 'nt':
			sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)
	
def main():
	host = gethostbyname(gethostname())
	print('START SNIFFING at [%s] for ICMP' %host)
	sniffing(host)
	
	
if __name__ == '__main__':
	main()
	