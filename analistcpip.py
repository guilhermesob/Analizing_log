import socket
import struct
import datetime

class SIEM:
    def __init__(self):
        self.events = []

    def log_event(self, event):
        self.events.append(event)
        print("Evento registrado no SIEM:", event)

    def analyze_packet(self, packet):
        version, ihl, ttl, protocol, source_ip, dest_ip = self.parse_ip_header(packet[:20])
        if protocol == 6:  # TCP protocol
            source_port, dest_port, sequence_number, ack_number, data_offset, flags, window_size = self.parse_tcp_header(packet[20:])
            timestamp = datetime.datetime.now()
            event = {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "source_port": source_port,
                "dest_port": dest_port,
                "protocol": "TCP",
                "flags": flags
            }
            self.log_event(event)
            self.detect_intrusion(event)

    def parse_ip_header(self, data):
        header = struct.unpack('!BBHHHBBH4s4s', data)
        version = header[0] >> 4
        ihl = header[0] & 0xF
        ttl = header[5]
        protocol = header[6]
        source_ip = socket.inet_ntoa(header[8])
        dest_ip = socket.inet_ntoa(header[9])
        return version, ihl, ttl, protocol, source_ip, dest_ip

    def parse_tcp_header(self, data):
        header = struct.unpack('!HHLLBBHHH', data)
        source_port = header[0]
        dest_port = header[1]
        sequence_number = header[2]
        ack_number = header[3]
        data_offset = (header[4] >> 4) * 4
        flags = header[5]
        window_size = header[6]
        return source_port, dest_port, sequence_number, ack_number, data_offset, flags, window_size

    def detect_intrusion(self, event):
        # Implementação simples de detecção de intrusões
        if event["flags"] & 0x02:  # Verifica se o pacote tem a flag SYN
            # Se encontrarmos um pacote com SYN, podemos registrar isso como uma tentativa de conexão não autorizada
            intrusion_event = {
                "timestamp": event["timestamp"],
                "source_ip": event["source_ip"],
                "dest_ip": event["dest_ip"],
                "source_port": event["source_port"],
                "dest_port": event["dest_port"],
                "event_type": "Tentativa de Conexão Não Autorizada",
            }
            self.log_event(intrusion_event)

    def correlate_events(self):
        # Implementação simples de correlação de eventos
        for i in range(len(self.events)):
            for j in range(i+1, len(self.events)):
                event1 = self.events[i]
                event2 = self.events[j]
                if (event1["source_ip"] == event2["dest_ip"] and
                        event1["dest_ip"] == event2["source_ip"] and
                        event1["source_port"] == event2["dest_port"] and
                        event1["dest_port"] == event2["source_port"]):
                    # Se encontrarmos dois eventos com IPs e portas opostas, podemos registrar isso como tráfego suspeito
                    correlation_event = {
                        "timestamp": datetime.datetime.now(),
                        "event_type": "Tráfego Suspeito",
                        "events": [event1, event2]
                    }
                    self.log_event(correlation_event)

def main():
    siem = SIEM()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        packet = s.recvfrom(65565)
        siem.analyze_packet(packet[0])
        siem.correlate_events()

if __name__ == "__main__":
    main()
          
