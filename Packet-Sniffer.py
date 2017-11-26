 #reference IP table http://www.networksorcery.com/enp/protocol/ip.html
import socket
import struct
import sys

def ethernet_unpack(pkt):
    dest_mac, src_mac,protocol= struct.unpack('!6s 6s H', pkt[:14])
    return mac_address(dest_mac), mac_address(src_mac) , socket.htons(protocol), pkt[14:]

#formating mac to AA:BB:CC format
def mac_address(address_data):
    bytes_string=B':'.join(["%02X" % (ord(x)) for x in address_data])
    return bytes_string.upper()


# To unpack the ip packet,
#ip version and header together form 8bits in the ip header table: hence B as it has size 1byte=8bits
#Differentaited services forms next 8bits in the header: hence B as it has size 1byte=8bits
#Total length, identification, (flags and fragment offset) forms the next 16bits each in the header: hence H as it hs size 2byte= 16bits
# TTL and Protocol occupies 8bits each in ip header: hence B each
#Header checksum= 16 bits . hecne H
#Source IP: 32 bits : hence 4s ( string of size 8*4)
#Destination IP: 32 bits : hence 4s ( string of size 8*4)
def IP_header_unpack(pkt):
    unpack_data= struct.unpack('!B B H H H B B H 4s 4s', pkt[:20])
    versionIHL= unpack_data[0] #unpack version and  IP header length

    version= versionIHL >> 4 # to extract version, bit shift by 4 bits as version occupies 4bits in iptable
    header_length =  versionIHL & 0xf

    # differentiated services not unpacked

    total_length=  unpack_data[2]
    identification= unpack_data[3]
    return version, header_length, total_length, identification



#getiing flag details:
#flags takes up 3 bits in the iptable.
# R (reserved bit) - 1bit size- values( 0- fragment if necessary, 1- do not fragment)
#MF (more fragments : 1bit  values( 0- this is last fragment, 1- more fragment follow this fragment)
def get_flags(pkt):
    flagR = {o: 'o: Reserved bits'}
    flagDF = {o: 'o: fragment if necessary', 1: '1: do not fragment'}
    flagMF = {o: 'o: last fragment', 1:' 1: more fragment to follow'}

# calculate R,DF, MF values:
    #calculate R value:
    #0x8000 in binary is 1000000000000000 which is 16 bits long. we need to get value at 15th position in the ipheader as 15th postiton corressponds to Reserved bits.
    #data till 16 bits are made zero and is then bit-shifted to right to 15th postions
    R= pkt & 0x8000
    R >>= 15
    





    

def main():
    connection= socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3)) #ntohs(3) checks whether the data is in readable format like byte order, big endian
    while True:
        try:
            raw_data, addr = connection.recvfrom(655536)
        except socket.timeout:
            print ' error in receiving data'

        dest_mac, src_mac,protocol,pkt= ethernet_unpack(raw_data)
        ip_version, header_length, total_length, identification = IP_header_unpack(raw_data)
        print (' dest_mac: ' +dest_mac + ' source_mac: '+ src_mac+' protocol: '+str(protocol))
        print ''
        print ('ip version: '+str(ip_version)+ ' header length: ' +str(header_length)+ ' total length: '+ str(total_length)+ ' identification: ' + str(identification))
        print''
        print''








main()