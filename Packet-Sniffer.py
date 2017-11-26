import socket
import struct
import sys

def ethernet_unpack(pkt):
    dest_mac, src_mac,protocol= struct.unpack('!6s 6s H', pkt[:14])
    return mac_address(dest_mac), mac_address(src_mac) , socket.htons(protocol), pkt[14:]

#formating mac to AA:BB:CC format
def mac_address(address_data):
    bytes_string=B':'.join(["%02X" % (ord(x)) for x in address_data])
    return bytes_string.upper() #maps the mac address in terms of ' aa bb cc dd' i.e 2bytes at a time
    #return ':'.join(mac_format).upper() #add : between 2 bytes and make the string uppercase


# To unpack the ip packet,
#ip version and header together form 8bits in the ip header table: hence B as it has size 1byte=8bits
#Differentaited services forms next 8bits in the header: hence B as it has size 1byte=8bits
#Total length, identification, (flags and fragment offset) forms the next 16bits each in the header: hence H as it hs size 2byte= 16bits
# TTL and Protocol occupies 8bits each in ip header: hence B each
#Header checksum= 16 bits . hecne H
#Source IP: 32 bits : hence 4s ( string of size 8*4)
#Destination IP: 32 bits : hence 4s ( string of size 8*4)
def IPv4_unpack(pkt):
    unpack_data= struct.unpack('!BBHHHBBH4s4s', pkt[:20])
    versionIHL= unpack_data[0] #unpack version and  IP header length
    version= versionIHL >> 4 # to extract version, bit shit by 4 bits as version occupies 4bits in iptable
    header_length =  versionIHL & 0xf
    print 'versionIHL ' + str(versionIHL)
    print 'version `' + str(version)
    print 'header length '+str(header_length)


    

def main():
    connection= socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3)) #ntohs(3) checks whether the data is in readable format like byte order, big endian
    while True:
        try:
            raw_data, addr = connection.recvfrom(655536)
        except socket.timeout:
            print ' error in receiving data'

        dest_mac, src_mac,protocol,pkt= ethernet_unpack(raw_data)
        IPv4_unpack(raw_data)
        print ' dest_mac ' +dest_mac
        print 'source_mac '+ src_mac
        print ' protocol '+str(protocol)








main()