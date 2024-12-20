from CovertChannelBase import CovertChannelBase
from scapy.all import IP, ICMP, sniff

class MyCovertChannel(CovertChannelBase):
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
        
        for i in range(0, len(binary_message), bit_len):
            chunk = binary_message[i:i + bit_len]
            seq_number = int(chunk, 2)
            packet = IP(dst="172.18.0.3") / ICMP(seq = seq_number)
            CovertChannelBase.send(self, packet)
        
            
        
    def receive(self, log_file_name, bit_length):
        """
        Sniffs packets and processes them chunk by chunk via using process_packet() function. Adds the sequence number
        field contents into received_bits array. Creates the decoded message by joining the received bits together.
        
        No encoding/decoding
        """
        received_bits = []
           
        def process_packet(packet):
            if packet.haslayer(ICMP):
                seq_number = packet[ICMP].seq
                binary_chunk = format(seq_number, f'0{bit_length}b')
                received_bits.append(binary_chunk)
                if binary_chunk.endswith("."):
                    return False
            return True

        sniff(filter="icmp", prn=process_packet, stop_filter=lambda pkt: not process_packet(pkt))
        decoded_message = '.'.join(received_bits)
        self.log_message(decoded_message, log_file_name)
        
