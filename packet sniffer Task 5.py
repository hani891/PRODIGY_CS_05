from scapy.all import *

def packet_handler(packet):
    """Handles captured packets."""
    answer=""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        if protocol == 1:  # ICMP
            answer=packet[ICMP].summary()
            print(answer)
        elif protocol == 6:  # TCP
            answer=packet[TCP].summary()
            print(answer)
        elif protocol == 17:  # UDP
            answer=packet[UDP].summary()
            print(answer)
        else:
            print("Payload Data:", packet.summary())
        print("Source IP: ",src_ip,"Destination IP:",dst_ip,"Protocol:",protocol,"\n")
        if packet.haslayer("Raw"):
            payload = packet[Raw].load
            print("data: ",payload,"\n")
        # Extract payload data based on the protocol
        
sniff(prn=packet_handler, filter="ip")