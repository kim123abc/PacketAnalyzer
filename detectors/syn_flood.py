from engine import PacketData, Flow

def detect(packet: PacketData, flow: Flow):

    print(f'flow.pps: {flow.pps}, flow.syn_count: {flow.syn_count}, flow.last_seen: {flow.last_seen}, flow.start_time: {flow.start_time}')
    print(packet.raw_packet)

    if flow.protocol != "TCP":
        return (False, "")

    if flow.syn_count > 100 and flow.pps > 50:

        print(
            "[SYN Flood]",
            packet.src_ip
        )
        return (True, "SYN Flood")
    
    return (False, "")
