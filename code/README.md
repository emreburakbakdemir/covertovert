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
    - **bit_len:** An integer representing the size of each binary chunk to be encoded in ICMP packet sequence numbers. Possible Values: {1,2,4,8,16}
    - **key:** A 16-bit integer masking the information for secure transmission.

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
    - **key:** A 16-bit integer reverting transmitted value into the real message.

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
1. **encoder(self,chunk,bit_len,key)**

    **Parameters**
    - **chunk:** A string representing a binary chunk of the message to be encoded.
    - **bit_len:** The length of the binary chunk to be encoded.
    - **key:** The integer used to encrypt the message.

    **Functionality**
    - Converts the binary chunk (chunk) into its decimal equivalent.
    - Generates a base number with respect to bit length.
    - Applies bitwise XOR (^) operation between chunk and key and adds base number to spread information in allowed 16-bit.
    - Returns the resulting sequence number, which encodes the binary chunk for transmission.

2. **decoder(self, seq, bit_len, key)**

    **Parameters**
    - **seq:**  The sequence number extracted from the ICMP packet.
    - **bit_len:** The length of the binary chunk being decoded.
    - **key:** The integer used to decrypt the message.

    **Functionality**
    - Generates the base number and subtracts it from the sequence number.
    - Applies bitwise XOR (^) operation between sequence number and key. Since bitwise XOR (^) is self-inverse it produces the message.
    - Converts the resulting value back into its binary representation and pads it with leading zeros to ensure it matches the bit_len.
    - Returns the binary chunk as a string, which represents the decoded data from the sequence number.

3. **process_packet(self, packet, bit_len, key)**

    **Parameters**
    - **self:** Reference to the instance of the **MyCovertChannel** class.
    - **packet:** Current sniffed packet which its sequence number will be decoded.
    - **bit_len:** An integer representing the size of each binary chunk encoded in the ICMP packet's sequence number.
    - **key:** A 16-bit integer reverting transmitted value into the real message.

    **Functionality**
    - Checks if the incoming packet contains an ICMP layer.
    - Extracts the sequence number from the ICMP layer of the packet.
    - Decodes the sequence number into a binary chunk using the custom decoding function **decoder(seq, bit_len, key)**.
    - Appends the decoded binary chunk to the **received_bits** buffer.
    - When enough bits are accumulated (8 bits):
        - Converts the binary string into its corresponding ASCII character using **convert_eight_bits_to_character()**.
        - Appends the character to the **decoded_message** list.
    - If receives more than 8 bits repeats above process until every byte arrived is processed.
    - Checks if the received character is the terminating character (.). If so, sets the termination flag **(self.flag)** to **True**, signaling the **sniff** function which uses **check_end()** function to stop capturing packets.
        - **check_end(self, packet)**
            - After **sniff** function sniffs a packet and processes it, **process_packet()** function updates the flag. **check_end()** function checks this flag for each processed packet and terminates the sniffing according to the flag. 


## Covert Channel Capacity
For **message_len:** 16 and **bit_len:** 1, covert channel capacity in bits per second is 12.250 bps
For **message_len:** 16 and **bit_len:** 2, covert channel capacity in bits per second is 24.579 bps
For **message_len:** 16 and **bit_len:** 4, covert channel capacity in bits per second is 46.097 bps
For **message_len:** 16 and **bit_len:** 8, covert channel capacity in bits per second is 93.027 bps
For **message_len:** 16 and **bit_len:** 16, covert channel capacity in bits per second is 184.046 bps