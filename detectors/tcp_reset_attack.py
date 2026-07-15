from engine import PacketData, Flow
from datetime import datetime


def detect(packet: PacketData, flow: Flow):

    if flow.protocol != "TCP":
        return False, None

    if flow.packet_count < 15:
        return False, None

    ack_count = getattr(flow, "ack_count", 0)
    fin_count = getattr(flow, "fin_count", 0)

    rst_ratio = flow.rst_count / flow.packet_count
    ack_ratio = ack_count / flow.packet_count
    fin_ratio = fin_count / flow.packet_count

    normal_close = fin_ratio >= 0.10

    session_reset_attack = (
        flow.syn_count > 0
        and flow.pps >= 50
        and flow.rst_count >= 20
        and rst_ratio >= 0.60
        and ack_ratio <= 0.40
        and not normal_close
    )

    rst_flood_attack = (
        flow.syn_count <= 2
        and flow.pps >= 50
        and flow.rst_count >= 20
        and rst_ratio >= 0.80
    )

    if session_reset_attack or rst_flood_attack:

        if session_reset_attack:
            attack_type = "TCP RESET ATTACK"
            threat = "HIGH"
        else:
            attack_type = "TCP RST FLOOD"
            threat = "CRITICAL"

        packet_time = getattr(packet, "timestamp", None)

        if isinstance(packet_time, (int, float)):
            log_time = datetime.fromtimestamp(packet_time)
        else:
            log_time = datetime.now()

        print("\n" + "=" * 70)
        print("🚨 TCP MALICIOUS TRAFFIC DETECTED 🚨")
        print("=" * 70)

        print(f"Time           : {log_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Attack Type    : {attack_type}")
        print(f"Threat Level   : {threat}")

        print("-" * 70)

        print(f"Source IP      : {packet.src_ip}")
        print(f"Destination IP : {packet.dst_ip}")

        if hasattr(packet, "src_port"):
            print(f"Source Port    : {packet.src_port}")

        if hasattr(packet, "dst_port"):
            print(f"Dest Port      : {packet.dst_port}")

        print(f"Protocol       : {flow.protocol}")

        print("-" * 70)

        print(f"Packet Count   : {flow.packet_count}")
        print(f"PPS            : {flow.pps:.2f}")

        print()

        print(f"SYN Count      : {flow.syn_count}")
        print(f"ACK Count      : {ack_count}")
        print(f"FIN Count      : {fin_count}")
        print(f"RST Count      : {flow.rst_count}")

        print()

        print(f"RST Ratio      : {rst_ratio:.2%}")
        print(f"ACK Ratio      : {ack_ratio:.2%}")
        print(f"FIN Ratio      : {fin_ratio:.2%}")

        if hasattr(flow, "backward_ratio"):
            print(f"Backward Ratio : {flow.backward_ratio:.2%}")

        print("-" * 70)

        print("Status         : ALERT GENERATED")

        print("=" * 70)

        return True, attack_type

    return False, None