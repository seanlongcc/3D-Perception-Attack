# Import the necessary Scapy modules
from scapy.all import *
from scapy.layers.inet import IP

# Read in the PCAP file using Scapy's rdpcap function
packets = rdpcap('test.pcapng')


def apply_scrambling_algorithm(packet):
    # Get the raw bytes of the packet
    packet_bytes = bytes(packet)

    # Perform the Caesar cipher on the packet bytes using a secret key
    secret_key = 5
    scrambled_bytes = b''
    for byte in packet_bytes:
        scrambled_bytes += bytes([(byte + secret_key) % 256])

    # Create a Scapy packet from the scrambled packet data
    packet_length = len(scrambled_bytes)
    scrambled_packet = IP(scrambled_bytes, len=packet_length)

    # Return the scrambled packet
    return scrambled_packet


# Iterate through each packet in the file and apply the scrambling algorithm
scrambled_packets = []
for packet in packets:
    scrambled_packet = apply_scrambling_algorithm(packet)
    scrambled_packets.append(scrambled_packet)

# Write the scrambled packets to a new PCAP file using Scapy's wrpcap function
wrpcap('output_file.pcapng', scrambled_packets)
