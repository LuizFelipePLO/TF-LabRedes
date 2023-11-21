#!/usr/bin/python3
import argparse
from socket import socket, AF_PACKET, SOCK_RAW, ntohs
from protocols import Protocols

ETH_P_ALL = 0x0003  # Constant for ETH_P_ALL to capture all protocols


class PacketDumper:
    def __init__(self, whitelist_protocols):
        self.whitelist_protocols = whitelist_protocols
        self.socket = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))

    def dump_packet(self, packet):
        decoded = Protocols.decode_eth(packet, self.whitelist_protocols)
        if decoded:
            self._dumpclean({"ETH": decoded})
            print()

    @staticmethod
    def _dumpclean(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, dict):
                    print(f"    [+]{key}")
                    PacketDumper._dumpclean(value)
                else:
                    print(f"\t{key}: {value}")
        else:
            print(obj)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', dest='wlist', nargs='+', help="Whitelist protocols for display",
                        choices=['ETH', 'ARP', 'IPv6', 'IPv4', 'ICMP', 'TCP', 'UDP', 'DNS', 'DHCP'])
    args = parser.parse_args()
    display_protocols = args.wlist if args.wlist else ['DHCP']

    dumper = PacketDumper(display_protocols)

    try:
        while True:
            packet, _ = dumper.socket.recvfrom(4096)
            dumper.dump_packet(packet)
    except KeyboardInterrupt:
        print("Packet capturing stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
