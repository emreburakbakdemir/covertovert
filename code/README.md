### **Covert Storage Channel that exploits Protocol Field Manipulation using Sequence Number field in ICMP**

## Project Overview
This project implements covert channel communication using ICMP packets. A binary message is encoded into the sequence numbers of ICMP packets, sent over the network, and decoded on the receiver side.

## Implementation Details
There are two main functions in MyCovertChannel class: send and receive. Communication is maintained with these two functions mainly. 

## Main Functions
1. **send(self, log_file_name, message_len, bit_len)**

    **Parameters**
    - **self:** Reference to the instance of the **MyCovertChannel** class.
    - **log_file_name:** A string specifying the file name to log the sent binary message.
    - **message_len:** An integer indicating the length of the binary message to be generated.
    - **bit_len:** An integer representing the size of each binary chunk to be encoded in ICMP packet sequence numbers.

    **Functionality**
    - Generates a random binary message using **generate_random_binary_message_with_logging()** function provided in CovertChannelBase.py file. The generated message is logged into the specified **log_file_name**
    - Splits the binary message into chunks which **len(chunk) = bit_len**
    - Encodes the binary message into ICMP packet sequence number and attaches it to the IP layer which is destined to the reciever IP.
    - Than sends the packets using **CovertChannelBase.send()** function. 


2. **receive(self, log_file_name, bit_length)**

    **Parameters**
    - **self:** Reference to the instance of the **MyCovertChannel** class.
    - **log_file_name:** A string specifying the file name to log the reconstructed binary message.
    - **bit_len:** An integer representing the size of each binary chunk encoded in ICMP packet sequence numbers.

    **Functionality**
    - Uses the **sniff** function from the Scapy library to capture incoming ICMP packets.
    - For each captured packet:
        - Extracts the sequence number from the ICMP layer.
        - Decodes the binary chunk using the custom decoding function.
        - Appends the decoded chunk to reconstruct the original binary message.
    - Stops the sniffing process once the terminating character (.) is received.
    - Logs the decoded binary message into the specified **log_file_name** .
    - The receiver ensures the reconstructed message matches the sent message for validation.

## Helper Functions
1. **encoder(self,chunk,bit_len)**

    **Parameters**
    - **chunk:** A string representing a binary chunk of the message to be encoded.
    - **bit_len:** The length of the binary chunk to be encoded.

    **Functionality**
    - Converts the binary chunk (chunk) into its decimal equivalent.
    - Generates a random base sequence number within a specified range, ensuring the value falls between $2^7$ and $2^14$, aligned with the given bit_len.
    - Adds the decimal value of the binary chunk to the random base sequence number.
    - Returns the resulting sequence number, which encodes the binary chunk for transmission.

2. **decoder(self, seq, bit_len)**

    **Parameters**
    - **seq:**  The sequence number extracted from the ICMP packet.
    - **bit_len:** The length of the binary chunk being decoded.

    **Functionality**
    - Extracts the encoded portion of the sequence number using modulo $2^(bit_len)$
    - Converts the resulting value back into its binary representation and pads it with leading zeros to ensure it matches the bit_len.
    - Returns the binary chunk as a string, which represents the decoded data from the sequence number.

3. **process_packet(self, packet, bit_len)**

    **Parameters**
    - **self:** Reference to the instance of the **MyCovertChannel** class.
    - **packet:** Current sniffed packet which its sequence number will be decoded.
    - **bit_len:** An integer representing the size of each binary chunk encoded in the ICMP packet's sequence number.

    **Functionality**
    - Checks if the incoming packet contains an ICMP layer.
    - Extracts the sequence number from the ICMP layer of the packet.
    - Decodes the sequence number into a binary chunk using the custom decoding function **decoder(seq, bit_len)**.
    - Appends the decoded binary chunk to the **received_bits** buffer.
    - When enough bits are accumulated (8 bits):
        - Converts the binary string into its corresponding ASCII character using **convert_eight_bits_to_character()**.
        - Appends the character to the **decoded_message** list.
    - Checks if the received character is the terminating character (.). If so, sets the termination flag **(self.flag)** to **True**, signaling the **sniff** function which uses **check_end()** function to stop capturing packets.
        - **check_end(self, packet)**
            - After **sniff** function sniffs a packet and processes it, **process_packet()** function updates the flag. **check_end()** function checks this flag for each processed packet and terminates the sniffing according to the flag. 


## Covert Channel Capacity
For **message_len:** 16 and **bit_len:** 2, covert channel capacity in bits per second is 22.224