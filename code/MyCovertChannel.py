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
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. 
        Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, message_len, message_len)
        
        for i in range(0, len(binary_message), bit_len):
            chunk = binary_message[i:i + bit_len]
            seq_number = int(chunk, 2)
            packet = IP(dst="172.18.0.3") / ICMP(seq = seq_number)
            CovertChannelBase.send(self, packet)
        
            
        
    def receive(self, log_file_name, bit_length):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, 
        the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
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
        
