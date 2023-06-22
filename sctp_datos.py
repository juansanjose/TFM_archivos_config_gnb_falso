import argparse
from scapy.all import *
from scapy.layers.sctp import SCTPChunkAbort


def process_sctp_packet(packet, source_ip):
    contador = 0

    layers = []
    current_layer = packet.getlayer(SCTP)
    while current_layer:
        layers.append(current_layer.name)
        current_layer = current_layer.payload if current_layer.payload else None

    # Print the expanded layers
    for layer in reversed(layers):
        ip = packet[IP]
        src_ip = ip.src
        if src_ip == source_ip:
            sctp = packet[SCTP]
            src_port = sctp.sport
            dst_port = sctp.dport
            vtag = sctp.tag

            if src_port is not None and dst_port is not None and vtag is not None:
                
                print("Destination Port:", dst_port)
                print("Source Port:", src_port)
                print("Verification Tag:", hex(vtag))

                sys.exit(0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help='Specify the network interface to use for the attack')
    parser.add_argument('-s', '--source', help='Specify the source IP address of the gNB node')
    
    #parser.parse_args(['-h'])

    args = parser.parse_args()

    if not(args.interface) or not(args.source) :
        parser.parse_args(['-h'])
    elif args.interface and args.source:
        
        # Sniff SCTP packets on the specified interface
        sniff(iface=args.interface, filter="sctp", prn=lambda pkt: process_sctp_packet(pkt, args.source))
    else:
        print("Invalid arguments. Use '-h' or '--help' for usage information.")

if __name__ == '__main__':
    main()
