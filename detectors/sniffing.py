from scapy.all import sniff, IP, TCP

# 실습 통계를 위한 누적 카운터 변수
stats = {
    "total_packets": 0,
    "ack_count": 0,
    "syn_count": 0,
    "rst_count": 0
}

def trace_sequence_numbers(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        payload_len = len(tcp_layer.payload)

        # 분석용 실시간 누적 카운트 증가
        stats["total_packets"] += 1
        
        # TCP 헤더 플래그 문자열 검사 ('A'=ACK, 'S'=SYN, 'R'=RST)
        flags_str = str(tcp_layer.flags)
        if "A" in flags_str:
            stats["ack_count"] += 1
        if "S" in flags_str:
            stats["syn_count"] += 1
        if "R" in flags_str:
            stats["rst_count"] += 1

        # ACK Ratio(비율) 계산 (0 나누기 방지 예외 처리)
        if stats["total_packets"] > 0:
            ack_ratio = stats["ack_count"] / stats["total_packets"]
        else:
            ack_ratio = 0.0

        # TCP 흐름 제어: 서버가 수용할 차기 기대 시퀀스 번호 계산
        next_expected_seq = tcp_layer.seq + payload_len

        # 모니터링 대시보드 출력
        print("\n" + "="*50)
        print(f"[포착] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        print(f" 현재 SEQ  : {tcp_layer.seq} | 데이터 크기: {payload_len} bytes")
        print(f"🎯 차기 SEQ 예측값: {next_expected_seq}")
        print(f"🎯 차기 ACK 예측값: {tcp_layer.ack}")
        print("-"*50)
        print(f"📊 실시간 누적 분석 통계 (총 패킷: {stats['total_packets']}개)")
        print(f"   └─ SYN 개수 : {stats['syn_count']}개")
        print(f"   └─ RST 개수 : {stats['rst_count']}개")
        print(f"   └─ ACK 개수 : {stats['ack_count']}개")
        print(f"   ✨ ACK Ratio : {ack_ratio:.2%}")
        print("="*50)

if __name__ == "__main__":
    # [💡 핵심 보완] 방어용 서버 IP(192.168.72.132)와 포트(9999)가 연관된 TCP 트래픽만 수집하도록 하단 필터 강제 고정
    TARGET_FILTER = "tcp and host 192.168.72.132 and port 9999"
    
    print(f"[*] 22버전 호스트: 타깃 서버[{TARGET_FILTER}] 전용 분석 엔진 가동...")
    sniff(filter=TARGET_FILTER, prn=trace_sequence_numbers)
