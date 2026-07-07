from engine import PacketData, Flow
from collections import defaultdict

scanned_ports = defaultdict(set)

def detect(packet: PacketData, flow: Flow):

    if flow.protocol != "UDP":
        return

    key = (packet.src_ip, packet.dst_ip)
    scanned_ports[key].add(packet.dst_port)

    if flow.duration < 2:
        return

    port_count = len(scanned_ports[key])
    
    if port_count < 20:
        return

    print(f"""
    [UDP Scan]
    공격 IP = {packet.src_ip}
    스캔한 포트 수 = {port_count}
    지속 시간 = {flow.duration:.2f}초
    """)

    scanned_ports[key].clear()