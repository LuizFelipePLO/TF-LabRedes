import ipaddress
from socket import inet_ntoa
from struct import Struct
import struct
from typing import Dict, List
from unittest import result


class Protocols():
    '''
    The Protocols class contains each protocol decoded support
    Attributes:
        ETH_HEADER (Struct): Ethernet header struct,
        IPV4_HEADER (Struct): IPv4 header struct,
        UDP_HEADER (Struct): UDP header struct,
        DHCP_HEADER (Struct): DHCP header struct,
    '''
    ETH_HEADER = Struct("!6s6sH")
    IPV4_HEADER = Struct("!2B3H2BH4s4s")
    UDP_HEADER = Struct("!4H")
    DHCP_HEADER = Struct("!4BI2H4s4s4s4s16s64s128sI")

    # Protocol Numbers
    PROTO_IPV4 = 0x0800
    PROTO_UDP = 17
    DHCP_MAGIC_COOKIE = 0x63825363

    @staticmethod
    def decode_eth(message, display: List) -> Dict:
        '''Decode ethernet packet
        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
        Returns:
            result (Dict): The decode result
        '''
        eth_header = Protocols.ETH_HEADER.unpack_from(message)
        dest_address, source_address, network_proto = eth_header
        dest_address = Protocols.format_mac(dest_address)
        source_address = Protocols.format_mac(source_address)

        result = {}
        if "ETH" in display:
            result.update({"Destine address": dest_address,
                           "Source address": source_address,
                           "Network protocol": network_proto})

        if network_proto == 2048:
            ipv4_header = Protocols.decode_ipv4(
                message, display, Protocols.ETH_HEADER.size)
            if ipv4_header:
                result.update({"IPv4": ipv4_header})

        return result

    @staticmethod
    def decode_ipv4(message, display: List, offset: int) -> Dict:
        '''Decode IPv4 packet
        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet offset
        Returns:
            result (Dict): The decode result
        '''
        ipv4_header = Protocols.IPV4_HEADER.unpack_from(message, offset)
        version_ihl, type_of_service, total_lenght, identifier, flags_offset, ttl, protocol, checksum, source_addr, dest_addr = ipv4_header

        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        flags = flags_offset >> 13
        off_set = flags_offset & 0x7FF

        source_addr = inet_ntoa(source_addr)
        dest_addr = inet_ntoa(dest_addr)

        result = {}
        if "IPv4" in display:
            result.update({"Version": version,
                           "Ihl": ihl,
                           "ToS": type_of_service,
                           "Total lenght": total_lenght,
                           "Identifier": identifier,
                           "Flags": flags,
                           "Offset": off_set,
                           "Ttl": ttl,
                           "Protocol": protocol,
                           "Checksum": checksum,
                           "Source address": source_addr,
                           "Destination address": dest_addr})

        if protocol == 17:
            udp_header = Protocols.decode_udp(
                message, display, offset+Protocols.IPV4_HEADER.size)
            if udp_header:
                result.update({"UDP": udp_header})

        return result

    @staticmethod
    def decode_udp(message, display: List, offset: int) -> Dict:
        '''Decode UDP packet
        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet + IPv4 offset
        Returns:
            result (Dict): The decode result
        '''
        udp_header = Protocols.UDP_HEADER.unpack_from(message, offset)
        source_port, dest_port, length, chekcsum = udp_header

        result = {}
        if "UDP" in display:
            result.update({"Source port": source_port,
                           "Destination port": dest_port,
                           "Length": length,
                           "Checksum": chekcsum})

        if source_port == 67 or source_port == 68:
            dhcp_header = Protocols.decode_dhcp(
                message, display, offset+Protocols.UDP_HEADER.size)
            if dhcp_header:
                result.update({"DHCP": dhcp_header})

        return result

    @staticmethod
    def decode_dhcp(message, display, offset):

        dhcp_header = Protocols.DHCP_HEADER.unpack_from(message, offset)
        op = dhcp_header[0]
        htype = dhcp_header[1]
        hlen = dhcp_header[2]
        hops = dhcp_header[3]
        xid = hex(dhcp_header[4])
        secs = dhcp_header[5]
        flags = dhcp_header[6]
        ciaddr = inet_ntoa(dhcp_header[7])
        yiaddr = inet_ntoa(dhcp_header[8])
        siaddr = inet_ntoa(dhcp_header[9])
        giaddr = inet_ntoa(dhcp_header[10])
        chaddr = Protocols.format_mac(dhcp_header[11])
        sname = Protocols.format_byte_array(dhcp_header[12])
        bootf = Protocols.format_byte_array(dhcp_header[13])
        offset = offset+Protocols.DHCP_HEADER.size
        result = {}

        # Protocols.perf_transport_layer["DHCP"] += 1

        if "DHCP" in display:
            result.update({"op": op,
                           "htype": htype,
                           "hlen": hlen,
                           "hops": hops,
                           "xid": xid,
                           "secs": secs,
                           "flags": flags,
                           "ciaddr": ciaddr,
                           "yiaddr": yiaddr,
                           "siaddr": siaddr,
                           "giaddr": giaddr,
                           "chaddr": chaddr,
                           "sname": sname,
                           "bootf": bootf})

        options = {}
        while offset < len(message):
            opt = message[offset]
            if opt == 255:  # End Option
                break
            offset += 1
            length = message[offset]
            offset += 1
            data = message[offset:offset+length]
            offset += length

            if opt == 53:  # DHCP Message Type
                data = data[0]
            elif opt == 50 or opt == 54:  # IP Addresses
                data = inet_ntoa(data)
            elif opt == 12:  # Host Name
                data = data.decode('ascii')

            options[opt] = {'length': length, 'data': data}

        result.update(options)
        return result

    @staticmethod
    def format_mac(mac_addr):
        return ':'.join(mac_addr.hex()[i:i+2] for i in range(0, len(mac_addr.hex()), 2))

    @staticmethod
    def format_byte_array(array):
        return ''.join(chr(b) for b in array if b != 0) or "not given"
