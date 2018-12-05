from socket import *
import os
import struct

def parse_ipheader(data):
	ipheader = struct.unpack('!BBHHHBBH4s4s' , data[:20])
	return ipheader

def getDatagramSize(ipheader):	
	return ipheader[2]	
	
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
	
	count = 1
	try:
		while True:
			data = recvData(sniffer)
			ipheader = parse_ipheader(data[:20])
			datagramSize = getDatagramSize(ipheader)
			protocol = getProtocol(ipheader)
			src_ip, dest_ip = getIP(ipheader)
			print('\nSNIFFED [%d] ++++++++++++++' %count)
			print('Datagram SIZE:\t%s' %str(datagramSize))
			print('Protocol:\t%s' %protocol)
			print('Source IP:\t%s' %src_ip)
			print('Destination IP:\t%s' %dest_ip)			
			count += 1
	except KeyboardInterrupt:  # Ctrl-C key input
		if os.name == 'nt':
			sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)
	
def main():
	host = gethostbyname(gethostname())
	print('START SNIFFING at [%s]' %host)
	sniffing(host)
	
	
if __name__ == '__main__':
	main()