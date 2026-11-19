def syn_scan(target, ports, progress=None):
    """Optional SYN scan. Requires Scapy, packet privileges and often Npcap on Windows."""
    try:
        from scapy.all import IP, TCP, sr
    except Exception as exc:
        raise RuntimeError(f"Scapy is not available: {exc}") from exc

    packets = [IP(dst=target)/TCP(dport=port, flags="S") for port in ports]
    answered, _ = sr(packets, timeout=2, verbose=0, retry=0)
    open_ports = []
    for sent, received in answered:
        if received.haslayer(TCP):
            flags = int(received[TCP].flags)
            if flags & 0x12 == 0x12:
                open_ports.append({
                    "port": int(sent[TCP].dport), "protocol": "tcp",
                    "state": "open", "service": "unknown", "product": "",
                    "version": "", "method": "scapy-syn"
                })
    return sorted(open_ports, key=lambda x: x["port"])
