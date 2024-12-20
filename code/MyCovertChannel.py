from random import randrange
from CovertChannelBase import CovertChannelBase
from scapy.all import IP, ICMP, sniff

class MyCovertChannel(CovertChannelBase):
    count = 0
    flag = False
    received_bits: str = ''
    decoded_message: list = []

    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, 
    the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, message_len, bit_len):
        """
        Creates a random binary message with logging. Slices the binary message into chunks. Creates IP layer with
        destination address of receiver (included in docker-compose.yaml file). Also creates an ICMP layer with 
        current chunk as a sequence number, than attaches the ICMP layer into IP layer. Later on, sends the packet using
        CovertChannelBase send function.
        
        Doesn't encode the binary message yet.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, message_len, message_len)
        binary_message += '00101110'
        print(binary_message)
        for i in range(0, len(binary_message), bit_len):
            chunk = binary_message[i:i + bit_len]
            seq_number = self.encoder(chunk, bit_len)
            packet = IP(dst="172.18.0.3") / ICMP(seq = seq_number)
            CovertChannelBase.send(self, packet)

    def encoder(self,chunk,bit_len):
        val = int(chunk,2)
        seq = randrange(2**7,2**14,2 ** bit_len)
        seq += val
        return seq
    
    def decoder(self, seq, bit_len):
        chunk = seq % 2 ** bit_len
        bin_chunk = bin(chunk)[2:].zfill(bit_len)
        return bin_chunk
        
    def process_packet(self, packet, bit_len):
        if packet.haslayer(ICMP):
            self.count += bit_len
            seq_number: int = packet[ICMP].seq
            self.received_bits += self.decoder(seq_number, bit_len)
            ascii_of_byte = ' '
            if not (self.count % 8): 
                string_of_byte = ''.join(self.received_bits[self.count-7:self.count])
                int_of_byte = int(string_of_byte,2)
                ascii_of_byte = chr(int_of_byte)
                self.decoded_message.append(ascii_of_byte)
            if ascii_of_byte == '.': self.flag = True
            
    def check_end(self, packet):
        return self.flag
    
    def receive(self, log_file_name, bit_length):
        """
        Sniffs packets and processes them chunk by chunk via using process_packet() function. Adds the sequence number
        field contents into received_bits array. Creates the decoded message by joining the received bits together.
        
        No encoding/decoding
        """
        
        self.count = 0

        sniff(
            filter="icmp and icmp[icmptype] != icmp-echoreply", 
            prn=lambda pkt: self.process_packet(pkt, bit_length),
            stop_filter=self.check_end)
            
        self.decoded_message = ''.join(self.decoded_message)
        self.log_message(self.decoded_message, log_file_name)
        
