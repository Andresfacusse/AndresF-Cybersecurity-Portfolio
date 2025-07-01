from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer("DNS"):
        print(packet.summary())

sniff(prn=packet_callback, store=0)
#works with Scappy
#Packet analysis, Scapy, networking
