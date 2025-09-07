from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "Other"

        print(f"[+] {ip_src} --> {ip_dst} | Protocol: {proto}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"    Payload: {payload[:50]}")

print("📡 Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False)
