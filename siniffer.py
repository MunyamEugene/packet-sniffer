import socket
import struct
import sys
import time 
from datetime import datetime

myInterface=input('provide pc interface :')
if myInterface == '':
    sys.exit()
def sniffInterface(intrfc='wlp3s0'):
    intrfc=myInterface
    return intrfc



try:
    scket=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
    scket.bind((sniffInterface(),0))
except socket.error as e:
    print(e)

def EthHeader(packet):
    eth_header=struct.unpack('!6s6sH',packet[0:14])
    src_mac_address=formatMacAddrs(eth_header[0])
    dst_mac_address=formatMacAddrs(eth_header[1])
    eth_type=socket.ntohs(eth_header[2])
    payload=packet[14:]
    return src_mac_address,dst_mac_address,eth_type,payload

def IPHeader(packet):
    ip_header=packet[:20]
    iph=struct.unpack('!BBHHHBBH4s4s',ip_header)
    ip_lenth=(iph[0]&15)*4
    protocal =iph[6]
    payload=packet[ip_lenth:]
    source_addr = socket.inet_ntoa(iph[8])
    dest_addr = socket.inet_ntoa(iph[9])
    return source_addr,dest_addr,protocal,ip_lenth

def TCPHeader(packet):
    tcp_header=struct.unpack('!HHLLBBHHH',packet[:20])
    src_port=tcp_header[0]
    dst_port=tcp_header[1]
    payload=packet[20:]
    return src_port,dst_port,payload

def UDPHeader(packet):
    udp_header=struct.unpack('!HHHH',packet[:8])
    src_port=udp_header[0]
    dst_port=udp_header[1]
    payload=packet[8:]
    return src_port,dst_port,payload

def getHostName(addrs):
    host_name=addrs
    try:
     host_name=socket.gethostbyaddr(addrs)[0]
    except socket.error as e:
        return host_name
    return host_name
def formatMacAddrs(mac):
    return ":".join(map("{:2x}".format,mac)).upper()
    

#receive multiple packets
try:
     while True:
        raw_data,addr=scket.recvfrom(65565)
        packet = raw_data
        src_mac,dst_mac,ethType,eth_payload=EthHeader(packet)

        print("TIMESTAMP:{}\n".format(datetime.fromtimestamp(time.time())))
        print("SOURCE MAC ADDRESS:{} ==> DST MAC ADDRESS:{}\n".format(dst_mac,src_mac))
        if ethType==8:
            src_ip,dst_ip,proto,ip_len=IPHeader(eth_payload)
            print("SOURCE HOST:{} ==> DST HOST:{}\n".format(getHostName(src_ip),getHostName(dst_ip)))
            if proto==6:
                src_port,dst_port,payload=TCPHeader(eth_payload[ip_len:])
                print("SOURCE IP:{} ==> PORT:{}\n".format(src_ip,src_port))
                print("DST IP:{} ==> PORT:{}\n".format(dst_ip,dst_port))
                print("paload:{}\n".format(payload))
            elif proto==17:
                src_port,dst_port,payload=UDPHeader(eth_payload[ip_len:])
                print("SOURCE IP:{} ==> PORT:{}\n".format(src_ip,src_port))
                print("DST IP:{} ==> PORT:{}\n".format(dst_ip,dst_port))
                print("paload:{}\n".format(payload))
        print("==============================================")
except KeyboardInterrupt:
    print("Application stoped")



    
    
