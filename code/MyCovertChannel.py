from random import randrange
from CovertChannelBase import CovertChannelBase
from scapy.all import IP, ICMP, sniff
import time

class MyCovertChannel(CovertChannelBase):
    count = 0
    flag = False
    received_bits: str = ''
    decoded_message: list = []

    def __init__(self):
        pass
    def send(self, log_file_name, message_len, bit_len, key, dest_ip):
        """
        Creates a random binary message with logging. Slices the binary message into chunks. Creates IP layer with
        destination address of receiver (included in docker-compose.yaml file). Also creates an ICMP layer with 
        encoded current chunk as a sequence number, than attaches the ICMP layer into IP layer. Later on, sends the packet using
        CovertChannelBase send function.
        """
        
        # start_time = time.time()
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, message_len, message_len)
        for i in range(0, len(binary_message), bit_len):
            chunk = binary_message[i:i + bit_len]
            seq_number = self.encoder(chunk, bit_len, key)
            packet = IP(dst=dest_ip) / ICMP(seq = seq_number) 
            CovertChannelBase.send(self, packet)
            
        # end_time = time.time()
        # transmission_time = end_time - start_time
        # bps = (message_len*8) / transmission_time
        # print("message length: ", message_len)
        # print("bit length: ", bit_len)
        # print("transmission time: ", transmission_time, "\n", "transmission rate (bps): ", bps)

    def encoder(self, chunk, bit_len, key):
        
        """
        Encrypts the chunk we will send to create secure connection. Uses self-inverse XOR operation to encode information. 
        And adds a base number calculated with the bit length of the chunk to spread the information to 16-bit sequence number.
        """        
        val = int(chunk, 2)
        base = 1 << (16-bit_len)
        encoded = val ^ key
        seq = base + encoded
        return seq 

    def decoder(self, seq, bit_len, key):
        """
        Decrypts the sequence number arrived into the message. Applies operations from encoder in reverse order to extract information.
        Subtracts base number from sequence number and XOR operation gives the binary representation of the message. Python's binary number indicator 0b
        is trimmed to safely concatenate with the message created up to this point.
        """
        
        base = 1 << (16-bit_len)
        encoded = seq - base
        val = encoded ^ key
        return bin(val)[2:].zfill(bit_len)
        
    def process_packet(self, packet, bit_len, key):
        if packet.haslayer(ICMP):
            seq_number: int = packet[ICMP].seq
            self.received_bits += self.decoder(seq_number, bit_len, key)
            ascii_of_byte = ''
            len_received_bits = len(self.received_bits)
            if not (len_received_bits % 8):
                while(len_received_bits/8 != self.count):
                    string_of_byte = ''.join(self.received_bits[self.count * 8: (self.count+1) * 8])
                    ascii_of_byte = self.convert_eight_bits_to_character(string_of_byte)
                    if(ascii_of_byte!='\0'): self.decoded_message.append(ascii_of_byte)
                    self.count+= 1
                    if ascii_of_byte == '.': 
                        self.flag = True
                        break
            
    def check_end(self, packet):
        return self.flag
    
    def receive(self, log_file_name, bit_length, key, source_ip):
        """
        Sniffs packets and processes them chunk by chunk via using process_packet() function. Adds the sequence number
        field contents into received_bits array. Creates the decoded message by joining the received bits together.
        """
        self.count = 0
        filter_string = f"icmp and icmp[icmptype] != icmp-echoreply and src host {source_ip}"
        sniff(
            filter=filter_string, 
            prn=lambda pkt: self.process_packet(pkt, bit_length, key),
            stop_filter=self.check_end)
        
        
        self.decoded_message = ''.join(self.decoded_message)
        self.log_message(self.decoded_message, log_file_name)
        
