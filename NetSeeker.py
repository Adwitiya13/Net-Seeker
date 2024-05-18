from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"    [TCP] Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"    [UDP] Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
        
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            print(f"    [Data] {raw_data}")

def start_sniffer(interface):
    print(f"[*] Starting sniffer on interface {interface}")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    start_sniffer(interface)

