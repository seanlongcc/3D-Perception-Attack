import os
import time
from PyQt5 import QtWidgets, QtCore
from scapy.all import *
from scapy.layers.inet import IP

# Create a new PyQt5 application
app = QtWidgets.QApplication([])

# Create a new PyQt5 window
window = QtWidgets.QWidget()

# Set the size of the window using the setGeometry() method
window.setGeometry(100, 100, 275, 100)

# Set the title of the window using the setWindowTitle() method
window.setWindowTitle('Packet Scrambler')

# Create a layout for the window
layout = QtWidgets.QVBoxLayout()

# Create a text field for entering the directory
directory_field = QtWidgets.QLineEdit()
directory_field.setPlaceholderText('Enter path to file')
layout.addWidget(directory_field)

# Create a text field for entering the file name
file_name_field = QtWidgets.QLineEdit()
file_name_field.setPlaceholderText('Enter output file name (optional)')
layout.addWidget(file_name_field)

# Create a button for starting the packet scrambling
scramble_button = QtWidgets.QPushButton('Scramble Packets')
layout.addWidget(scramble_button)

# Create a progress bar for displaying the progress percentage
progress_bar = QtWidgets.QProgressBar()

# Set the minimum and maximum values for the progress bar
progress_bar.setMinimum(0)
progress_bar.setMaximum(100)

# Set the text format for displaying the progress percentage
# he '%v' placeholder will be replaced with the current progress value
progress_bar.setFormat('%v%')
layout.addWidget(progress_bar)

# Set the text to be visible inside the progress bar and set it to 0%
progress_bar.setAlignment(QtCore.Qt.AlignCenter)
progress_bar.setValue(int(0))


def progressBar():
    # Reset progress bar
    progress_bar.setValue(int(0))
    # Get the directory
    directory = directory_field.text()
    count = 0
    # Read in the PCAP file using Scapy's rdpcap function
    packets = rdpcap(directory)
    # Iterate through each packet in the file and apply the scrambling algorithm
    for _ in packets:
        count += 1

    return count


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


def bitflip_corrupt(packet, weight: float = 0.2, min_bits: int = 1, max_bits: int = 8):
    """flips bits with given probability weight per byte and min/max bits to flip per byte"""
    # convert packet to list for operations
    contents_list = list(bytes(packet))

    # sanity checks
    if max_bits > 8:
        raise ValueError()
    if min_bits < 0:
        raise ValueError()
    if min_bits > max_bits:
        raise ValueError()
    if (weight <= 0) or (weight > 1):
        raise ValueError()

    # bitflipping logic starts here
    new_contents_list = []
    for byte in contents_list:
        if random.random() <= weight:
            # generate the bit-flipper byte
            bits = random.randint(min_bits, max_bits)
            flipped_bits = random.sample(range(8), bits)
            flipper = sum([2**i for i in flipped_bits])
            # xors flipper with original value
            new_byte = byte ^ flipper
        else:
            new_byte = byte
        new_contents_list.append(new_byte)

    # Create a Scapy packet from the scrambled packet data
    new_contents = bytes(new_contents_list)
    packet_length = len(new_contents_list)
    new_packet = IP(new_contents, len=packet_length)
    return new_packet


def one_corrupt(packet, weight: float = 0.2, min_bits: int = 1, max_bits: int = 8):
    """flips bits with given probability weight per byte and min/max bits to flip per byte"""
    # convert packet to list for operations
    contents_list = list(bytes(packet))

    # sanity checks
    if max_bits > 8:
        raise ValueError()
    if min_bits < 0:
        raise ValueError()
    if min_bits > max_bits:
        raise ValueError()
    if (weight <= 0) or (weight > 1):
        raise ValueError()

    # bitflipping logic starts here
    new_contents_list = []
    for byte in contents_list:
        if random.random() <= weight:
            # generate the bit-flipper byte
            bits = random.randint(min_bits, max_bits)
            oner_bits = random.sample(range(8), bits)
            oner = sum([2**i for i in oner_bits])
            # xors flipper with original value
            new_byte = byte | oner
        else:
            new_byte = byte
        new_contents_list.append(new_byte)

    # Create a Scapy packet from the scrambled packet data
    new_contents = bytes(new_contents_list)
    packet_length = len(new_contents_list)
    new_packet = IP(new_contents, len=packet_length)
    return new_packet


def zero_corrupt(packet, weight: float = 0.2, min_bits: int = 1, max_bits: int = 8):
    """zeroes bits with given probability weight per byte and min/max bits to zero per byte"""
    # convert packet to list for operations
    contents_list = list(bytes(packet))

    # sanity checks
    if max_bits > 8:
        raise ValueError()
    if min_bits < 0:
        raise ValueError()
    if min_bits > max_bits:
        raise ValueError()
    if (weight <= 0) or (weight > 1):
        raise ValueError()

    # bitflipping logic starts here
    new_contents_list = []
    for byte in contents_list:
        if random.random() <= weight:
            # generate the bit-zero byte
            bits = random.randint(min_bits, max_bits)
            zeroer_bits = random.sample(range(8), 8 - bits)
            zeroer = sum([2**i for i in zeroer_bits])
            # xors flipper with original value
            new_byte = byte & zeroer
        else:
            new_byte = byte
        new_contents_list.append(new_byte)
    return new_contents_list


def deletion_corrupt(contents_list: list, weight: float = 0.2):
    """removes bytes with given probability weight per byte"""
    # sanity checks
    if (weight <= 0) or (weight > 1):
        raise ValueError()

    # bitflipping logic starts here
    new_contents_list = []
    for byte in contents_list:
        if random.random() <= weight:
            pass
        else:
            new_byte = byte
            new_contents_list.append(new_byte)

    # Create a Scapy packet from the scrambled packet data
    new_contents = bytes(new_contents_list)
    packet_length = len(new_contents_list)
    new_packet = IP(new_contents, len=packet_length)
    return new_packet


def ScramblePackets():
    # Get the directory and file name from the text fields
    directory = directory_field.text()
    file_name = file_name_field.text()

    if os.path.exists(directory) == True:
        # If no file name was entered, generate a unique file name using the current timestamp
        if not file_name:
            timestamp = int(time.time())
            file_name = f'scrambled_{timestamp}.pcapng'
        else:
            # Append '.pcapng' to the file name if it is not already present
            if not file_name.endswith('.pcapng'):
                file_name += '.pcapng'

        # Get the total number of packets
        total_packets = progressBar()

        # Counter for progress bar
        count = 0

        # Read in the PCAP file using Scapy's rdpcap function
        packets = rdpcap(directory)

        # Iterate through each packet in the file and apply the scrambling algorithm
        scrambled_packets = []
        for packet in packets:
            scrambled_packet = apply_scrambling_algorithm(packet)
            scrambled_packets.append(scrambled_packet)
            # Increase counted file by one
            count += 1

            # Calculate the current progress as a percentage
            progress = (count + 1) / total_packets * 100

            # Convert the progress value to an integer before setting it on the progress bar
            progress_bar.setValue(int(progress))

        # Write the scrambled packets to a new PCAP file using Scapy's wrpcap function
        wrpcap(file_name, scrambled_packets)

    else:
        # Handle the error
        print("The directory does not exist or you do not have permission to access it.")


# Connect the 'returnPressed' signal of the directory_field to the ScramblePackets function
directory_field.returnPressed.connect(ScramblePackets)

# Connect the 'returnPressed' signal of the file_name_field to the ScramblePackets function
file_name_field.returnPressed.connect(ScramblePackets)

# Connect the 'clicked' signal of the scramble_button to the ScramblePackets function
scramble_button.clicked.connect(ScramblePackets)

# Set the layout of the window
window.setLayout(layout)

# Show the window
window.show()

# Run the application
app.exec_()
