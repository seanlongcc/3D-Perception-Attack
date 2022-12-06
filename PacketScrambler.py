import os
import time
import random
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QIntValidator, QFont
from PyQt5.QtCore import Qt
from scapy.all import *
from scapy.layers.inet import IP
import threading
import gc

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

# Create a text field for entering the corruption level
corruption_field = QtWidgets.QLineEdit()
corruption_field.setPlaceholderText(
    'Enter corruption weight from 1-100')

# Create a text field for entering the corruption level
proportion_field = QtWidgets.QLineEdit()
proportion_field.setPlaceholderText(
    'Enter proportion of packets to corrupt from 1%-100%')

# Create an integer validator and set it on the text field with a range of 1-100
validator = QIntValidator()
validator.setRange(1, 100)
corruption_field.setValidator(validator)
layout.addWidget(corruption_field)
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

# Create a new label for the Progress bar
progress_label = QtWidgets.QLabel('Progress')
progress_label.setAlignment(Qt.AlignCenter)
layout.addWidget(progress_label)

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


def on_text_changed():
    # Get the current text in the text field
    text = corruption_field.text()

    # Check if the text is a number greater than 100
    if text.isdigit() and int(text) > 100:
        # Set the text to 100 if it is greater than 100
        corruption_field.setText("100")

        # Move the cursor to the end of the text field
        cursor = corruption_field.cursorPosition()
        corruption_field.setCursorPosition(cursor)

    # Get the current text in the text field
    text = proportion_field.text()

    # Check if the text is a number greater than 100
    if text.isdigit() and int(text) > 100:
        # Set the text to 100 if it is greater than 100
        proportion_field.setText("100")

        # Move the cursor to the end of the text field
        cursor = proportion_field.cursorPosition()
        proportion_field.setCursorPosition(cursor)


# Connect the textChanged signal to the custom slot
corruption_field.textChanged.connect(on_text_changed)
proportion_field.textChanged.connect(on_text_changed)


def progressBar(directory):
    # Reset progress bar
    progress_bar.setValue(int(0))
    # Set Variables
    count = 0
    # Iterate through each packet in the file and apply the scrambling algorithm
    for _ in PcapReader(directory):
        count += 1
    return count


def scrambling_algorithm(packet, weight):
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


def bitflip_corrupt(packet, weight=0.2, min_bits: int = 1, max_bits: int = 8):
    # flips bits with given probability weight per byte and min/max bits to flip per byte
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
    # flips bits with given probability weight per byte and min/max bits to flip per byte
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
    # zeroes bits with given probability weight per byte and min/max bits to zero per byte
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

    # Create a Scapy packet from the scrambled packet data
    new_contents = bytes(new_contents_list)
    packet_length = len(new_contents_list)
    new_packet = IP(new_contents, len=packet_length)
    return new_packet


def progressBarUpdate(count=0, total_packets=1):
    # Increase counted file by one
    count += 1

    # Calculate the current progress as a percentage
    progress = (count + 1) / total_packets * 100

    # Convert the progress value to an integer before setting it on the progress bar
    progress_bar.setValue(int(progress))
    return count


def ScramblePackets(scrambling_method=None):
    # Get the directory and file name from the text fields
    directory = directory_field.text()
    file_name = file_name_field.text()

    if directory.endswith('.pcap') or directory.endswith('.pcapng'):
        # Sets a default weight and proportion
        weight = .2
        proportion = .2

        # Sets the custom weight
        if corruption_field.text() != '':
            weight = int(corruption_field.text()) * .01
        if proportion_field.text() != '':
            proportion = int(proportion_field.text()) * .01

        if os.path.exists(directory) == True:
            # If no file name was entered, generate a unique file name using the current timestamp
            if not file_name:
                timestamp = int(time.time())
                file_name = f'{scrambling_method.__name__}_{timestamp}.pcapng'
            else:
                # Append '.pcapng' to the file name if it is not already present
                if not file_name.endswith('.pcapng'):
                    file_name += '.pcapng'

            # start a timer
            start_time = time.time()

            # Get the total number of packets
            total_packets = progressBar(directory)

            # Counter for progress bar
            count = 0

            # Print out input values
            if scrambling_method != scrambling_algorithm:
                print(
                    f'{scrambling_method.__name__} with weight {int(weight * 100)} and proportion {int(proportion * 100)} started in {round(time.time() - start_time, 2)} seconds.')
            else:
                print(
                    f'{scrambling_method.__name__} with proportion {int(proportion * 100)} started in {round(time.time() - start_time, 2)} seconds.')

            # Iterate through each packet in the file and apply the scrambling algorithm
            scrambled_packets = []

            # for packet in PcapReader(directory):
            for packet in PcapReader(directory):
                if random.random() <= proportion:
                    scrambled_packet = scrambling_method(packet, weight)
                else:
                    scrambled_packet = packet
                scrambled_packets.append(scrambled_packet)
                count = progressBarUpdate(count, total_packets)

            # Write the scrambled packets to a new PCAP file using Scapy's wrpcap function
            wrpcap(file_name, scrambled_packets)

            # Print success message
            if scrambling_method != scrambling_algorithm:
                print(
                    f'{scrambling_method.__name__} with weight {int(weight * 100)} and proportion {int(proportion * 100)} SUCCESS in {round(time.time() - start_time, 2)} seconds.')

            else:
                print(
                    f'{scrambling_method.__name__} with proportion {int(proportion * 100)} SUCCESS in {round(time.time() - start_time, 2)} seconds.')

            # free up the memory
            del scrambled_packets
            gc.collect()

        else:
            # Handle the error
            print(
                "The directory does not exist or you do not have permission to access it.")

    else:
        print("File type not supported.")


def ScrambleMethodScramble():
    ScramblePackets(scrambling_algorithm)


def ScrambleMethodBitFlip():
    ScramblePackets(bitflip_corrupt)


def ScrambleMethodOne():
    ScramblePackets(one_corrupt)


def ScrambleMethodZero():
    ScramblePackets(zero_corrupt)


# start another thread for the progress bar, set to daemon so that it stops when the window closes
progressThread = threading.Thread(target=progressBarUpdate, daemon=True)
progressThread.start()

# Connect the 'clicked' signal of the a to the ScramblePackets function
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
