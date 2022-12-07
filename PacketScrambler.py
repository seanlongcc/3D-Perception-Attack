from numpy import bitwise_xor, bitwise_or, bitwise_and
import os
import time
import random
import dpkt
from PyQt5 import QtWidgets
from PyQt5.QtGui import QIntValidator, QFont
from PyQt5.QtCore import Qt
from scapy.all import *
from scapy.layers.inet import IP
from datetime import datetime

# Create a new PyQt5 application
app = QtWidgets.QApplication([])

# Create a new PyQt5 window
window = QtWidgets.QWidget()

# Set the size of the window using the setGeometry() method
window.setGeometry(100, 100, 350, 100)

# Set the title of the window using the setWindowTitle() method
window.setWindowTitle('Packet Scrambler')

# Create a layout for the window
layout = QtWidgets.QVBoxLayout()

# Set the font of the label
font = QFont("Arial", 12)

# Create a new label for the title
title_label = QtWidgets.QLabel('Packet Scrambler')
title_label.setFont(font)
title_label.setAlignment(Qt.AlignCenter)
layout.addWidget(title_label)

# Create a text field for entering the directory
directory_field = QtWidgets.QLineEdit()
directory_field.setPlaceholderText('Enter path to file')
layout.addWidget(directory_field)

# Create a new label for the Optional settings
options_label = QtWidgets.QLabel('Options')
options_label.setAlignment(Qt.AlignCenter)
layout.addWidget(options_label)

# Create a text field for entering the file name
file_name_field = QtWidgets.QLineEdit()
file_name_field.setPlaceholderText('Enter output file name')
layout.addWidget(file_name_field)

# Create a text field for entering the proportion level
proportion_field = QtWidgets.QLineEdit()
proportion_field.setPlaceholderText(
    'Enter proportion of packets to corrupt from 0%-100%')

# Create an integer validator and set it on the text field with a range of 1-100
validator = QIntValidator()
validator.setRange(0, 100)
proportion_field.setValidator(validator)
layout.addWidget(proportion_field)

# Create a new label for the modes
mode_label = QtWidgets.QLabel('Scramble Modes')
mode_label.setAlignment(Qt.AlignCenter)
layout.addWidget(mode_label)

# Create a button for starting the packet scrambling
scramble_button = QtWidgets.QPushButton('Scramble Packets')
layout.addWidget(scramble_button)

# Create a button for starting the packet scrambling
bitflip_button = QtWidgets.QPushButton('Bit Flip Packets')
layout.addWidget(bitflip_button)

# Create a button for starting the packet scrambling
one_button = QtWidgets.QPushButton('One Corrupt Packets')
layout.addWidget(one_button)

# Create a button for starting the packet scrambling
zero_button = QtWidgets.QPushButton('Zero Corrupt Packets')
layout.addWidget(zero_button)

# Create a QMessageBox object
msg = QtWidgets.QMessageBox()

# Set the message and the icon
msg.setText("Scrambling SUCCESS")
msg.setIcon(msg.Information)


def on_text_changed():
    # Get the current text in the text field
    text = proportion_field.text()

    # Check if the text is a number greater than 100
    if text.isdigit() and int(text) > 100:
        # Set the text to 100 if it is greater than 100
        proportion_field.setText("100")

        # Move the cursor to the end of the text field
        cursor = proportion_field.cursorPosition()
        proportion_field.setCursorPosition(cursor)

    # Check if the text is a number less than 1
    if text.isdigit() and int(text) < 0:
        # Set the text to 1 if it is less than 1
        proportion_field.setText("0")

        # Move the cursor to the end of the text field
        cursor = proportion_field.cursorPosition()
        proportion_field.setCursorPosition(cursor)


# Connect the textChanged signal to the proportion field
proportion_field.textChanged.connect(on_text_changed)


def scrambling_algorithm(packet):
    # Get the raw bytes of the packet
    packet_bytes = bytes(packet)

    # Perform the Caesar cipher on the packet bytes using a secret key
    secret_key = 5
    scrambled_bytes = bytearray()
    for byte in packet_bytes:
        scrambled_bytes.append((byte + secret_key) % 256)

    # Create a Scapy packet from the scrambled packet data
    packet_length = len(scrambled_bytes)
    scrambled_packet = IP(bytes(scrambled_bytes), len=packet_length)

    # Return the scrambled packet
    return scrambled_packet


def bitflip_corrupt(packet):
    # Convert packet to bytes for operations
    contents = bytes(packet)

    # Bitflipping logic starts here
    new_contents = bytearray()
    for byte in contents:
        # Generate the bit-flipper byte
        flipper = 255
        new_contents.append(bitwise_xor(byte, flipper))

    # Create a Scapy packet from the scrambled packet data
    packet_length = len(new_contents)
    new_packet = IP(bytes(new_contents), len=packet_length)
    return new_packet


def one_corrupt(packet):
    # Convert packet to bytes for operations
    contents = bytes(packet)
    packet_length = len(contents)

    # One-corrupt logic starts here
    new_contents = b'\xff' * packet_length

    # Create a Scapy packet from the scrambled packet data
    new_packet = IP(new_contents, len=packet_length)
    return new_packet


def zero_corrupt(packet, min_bits: int = 1, max_bits: int = 8):
    # Convert packet to bytes for operations
    contents = bytes(packet)

    # Sanity checks
    if max_bits > 8:
        raise ValueError()
    if min_bits < 0:
        raise ValueError()
    if min_bits > max_bits:
        raise ValueError()

    # Zero-corrupt logic starts here
    new_contents = bytearray()
    for byte in contents:
        # Generate the zero-corrupt byte
        bits = random.randint(min_bits, max_bits)
        zero_corrupt_bits = random.sample(range(8), 8 - bits)
        zero_corruptor = 0
        for bit in zero_corrupt_bits:
            zero_corruptor |= 1 << bit
        # Ands zero-corruptor with original value
        new_contents.append(bitwise_and(byte, zero_corruptor))

    # Create a Scapy packet from the scrambled packet data
    packet_length = len(new_contents)
    new_packet = IP(bytes(new_contents), len=packet_length)
    return new_packet


def ScramblePackets(scrambling_method):
    # Get the directory and file name from the text fields
    directory = directory_field.text()
    file_name = file_name_field.text()

    # Check if the directory ends with '.pcap' or '.pcapng'
    if directory.endswith('.pcap'):
        file_type = 'pcap'
    elif directory.endswith('.pcapng'):
        file_type = 'pcapng'
    else:
        print("File type not supported.")
        return

    # Set the proportion to the value entered in the proportion_field text field, or to 0.2 if the text field is empty
    proportion = int(proportion_field.text()
                     ) * .01 if proportion_field.text() else 0.2

    if os.path.exists(directory) == True:
        # If no file name was entered, generate a unique file name using a UUID
        if not file_name:
            timestamp = int(time.time())
            file_name = f'{scrambling_method.__name__}_{timestamp}.{file_type}'
        else:
            # Append the file type to the file name if it is not already present
            if not file_name.endswith(file_type):
                file_name += f'.{file_type}'

        # start a timer
        start_time = time.time()

        # Get current time
        def current_time():
            return datetime.now().strftime("%H:%M:%S")

        # Print out input values
        print(
            f'{scrambling_method.__name__} with proportion {int(proportion * 100)} started at {current_time()}.')

        # Open the new file, file_name, to write to in bytes
        with open(file_name, 'wb') as f:
            # Create a dpkt.pcap.Writer object
            pcap_writer = dpkt.pcap.Writer(f)

            # Read pcap file iteratively using scapy Pcapreader
            packet_counter = 1
            for packet in PcapReader(directory):
                if random.random() <= proportion:
                    scrambled_packet = scrambling_method(packet)
                else:
                    scrambled_packet = packet

                # Write the scrambled packets to a new PCAP file using dkpt
                pcap_writer.writepkt(scrambled_packet)
                if packet_counter % 1000 == 0:
                    print("Wrote packet", packet_counter, "at", current_time())
                packet_counter += 1

        # Print success message
        print(f'{scrambling_method.__name__} with proportion {int(proportion * 100)} SUCCESS in {round(time.time() - start_time, 2)} seconds at {current_time()}.\n')

        # Message box for success message
        msg.exec_()

    # Handle errors
    else:
        print(
            "The file does not exist or you do not have permission to access it.")


def ScrambleMethodScramble():
    ScramblePackets(scrambling_algorithm)


def ScrambleMethodBitFlip():
    ScramblePackets(bitflip_corrupt)


def ScrambleMethodOne():
    ScramblePackets(one_corrupt)


def ScrambleMethodZero():
    ScramblePackets(zero_corrupt)


# Connect the 'clicked' signal to the ScramblePackets function
scramble_button.clicked.connect(ScrambleMethodScramble)
bitflip_button.clicked.connect(ScrambleMethodBitFlip)
one_button.clicked.connect(ScrambleMethodOne)
zero_button.clicked.connect(ScrambleMethodZero)

# Set the layout of the window
window.setLayout(layout)

# Show the window
window.show()

# Run the application
app.exec_()
