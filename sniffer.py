import logging

from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from scapy.sendrecv import sniff

logger = logging.getLogger(__name__)


def packet_callback(packet):
    print(packet)
    print('packet.haslayer(TCP) - ', packet.haslayer(TCP))
    print('packet.haslayer(Raw) - ', packet.haslayer(Raw))
    print('packet.haslayer(IP) - ', packet.haslayer(IP))

    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        payload = packet[Raw].load.decode(errors='ignore')  # Игнорируйте ошибки декодирования
        if "eval(\"alert('XSS')\")" in payload:
            logger.warning("[*] Обнаружен XSS пейлоад в пакете!")
            logger.warning(f"[*] Листинг пакета:\n{payload}")


def start_sniffer():
    sniff(filter="tcp port 80", prn=packet_callback, store=0)


if __name__ == '__main__':
    start_sniffer()
