import socket
import struct

def ethernet_unpack(pkt):
    dest_mac, src_mac,protocol= struct.unpack('!6s 6s H', pkt[:14])
    return mac_address(dest_mac), mac_address(src_mac), socket.htons(protocol), data[14:]

#formating mac to AA:BB:CC format
def mac_address(address_data):
    mac_format= map('{0:02x}'.format, address_data) #maps the mac address in terms of ' aa bb cc dd' i.e 2bytes at a time
    return ':'.join(mac_format).upper() #add : between 2 bytes and make the string uppercase

def main():
    connection= socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3)) #ntohs(3) checks whether the data is in readable format like byte order, big endian
    while True:
        raw_data, addr = connection.recvfrom(655536)
        dest_mac, src_mac,protocol= ethernet_unpack(raw_data)
        print ' dest_mac ' +dest_mac
        print 'source_mac '+ src_mac
        print ' protocol '+protocol







main()