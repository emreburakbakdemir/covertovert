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
    def send(self, log_file_name, message_len, bit_len, key):
        """
        Creates a random binary message with logging. Slices the binary message into chunks. Creates IP layer with
        destination address of receiver (included in docker-compose.yaml file). Also creates an ICMP layer with 
        encoded current chunk as a sequence number, than attaches the ICMP layer into IP layer. Later on, sends the packet using
        CovertChannelBase send function.
        """
        
        start_time = time.time()
        
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, message_len, message_len)
        binary_message += '00101110'
        for i in range(0, len(binary_message), bit_len):
            chunk = binary_message[i:i + bit_len]
            seq_number = self.encoder(chunk, bit_len, key)
            packet = IP(dst="172.18.0.3") / ICMP(seq = seq_number) 
            CovertChannelBase.send(self, packet)
            
        end_time = time.time()
        transmission_time = end_time - start_time
        bps = (message_len*8) / transmission_time
        print("bit length: ", bit_len)
        print("transmission time: ", transmission_time, "\n", "transmission rate (bps): ", bps)

    def encoder(self, chunk, bit_len, key):
        

        val = int(chunk, 2)
        base = 1 << (16-bit_len)
        encoded = val ^ key
        seq = base + encoded
        return seq 

    def decoder(self, seq, bit_len, key):
        base = 1 << (16-bit_len)
        encoded = seq - base
        val = encoded ^ key
        return bin(val)[2:].zfill(bit_len)
        
    def process_packet(self, packet, bit_len, key):
        if packet.haslayer(ICMP):
            seq_number: int = packet[ICMP].seq
            self.received_bits += self.decoder(seq_number, bit_len, key)
            ascii_of_byte = ' '
            len_received_bits = len(self.received_bits)

            if not (len_received_bits % 8):
                while(len_received_bits/8 != self.count):
                    string_of_byte = ''.join(self.received_bits[self.count * 8: (self.count+1) * 8])
                    ascii_of_byte = self.convert_eight_bits_to_character(string_of_byte)
                    self.decoded_message.append(ascii_of_byte)
                    self.count+= 1
            if ascii_of_byte == '.': self.flag = True
            
    def check_end(self, packet):
        return self.flag
    
    def receive(self, log_file_name, bit_length, key):
        """
        Sniffs packets and processes them chunk by chunk via using process_packet() function. Adds the sequence number
        field contents into received_bits array. Creates the decoded message by joining the received bits together.
        """
        
        self.count = 0

        sniff(
            filter="icmp and icmp[icmptype] != icmp-echoreply", 
            prn=lambda pkt: self.process_packet(pkt, bit_length, key),
            stop_filter=self.check_end)

            
        self.decoded_message = ''.join(self.decoded_message)
        self.log_message(self.decoded_message, log_file_name)
        
