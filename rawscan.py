

import socket, struct, random, time

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i  in range(0, len(data), 2):
        s += (data[i] << 8) + data [i + 1]
    s = (s >> 16) + (s & 0xffff)
    s+= s >> 16
    return ~s & 0xffff

def build_tcp_syn(src_ip, dst_ip, src_port, dst_port):
    
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 20
    ip_id = random.randrange(0, 65536)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0     
    ip_saddr = socket.inet_aton(src_ip)
    ip_header = struct.pack("!BBHHhBBH4s4s",
                            (ip_ver << 4) + ip_ihl, ip_tos,ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    ip_check = checksum(ip_header)
    ip_header = struct.pack("!BBBBBBBB4s4s",
                            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len, ip_is, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    tcp_seq = random.randrange(0, 2**32)
    tcp_ack = 0
    tcp_doff = 5
    tcp_flags = 0x02
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_header = struct.pack("!HHLLBBHHH",
                             src_port, dts_port, tcp_seq, tcp_ack, (tcp_doff << 4), tcp_flags,tcp_window, tcp_check, tcp_urg_ptr)
    return ip_header + tcp_header

def raw_syn_scan(dst_ip, dst_port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.Sock_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        return None
    
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    src_port = random.randrange(1024, 65535)
    
    try:
        src_ip = socket.gethostnyname(socket.gethostname())
    except Exception:
        src_ip = "127.0.0.1"
        
    pkt = build_tcp_syn(src_ip, dst_ip, src_port, dst_port)
    s.sendto(pkt, (dst_ip, 0))
    s.settimeout(timeout)
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            break
        if len(data) < 40:
            continue
        ip_hdr = data[:20]
        proto = ip_hdr[9]
        if proto != socket.IPPROTO_TCP:
            continue
        src = socket.inet_ntoa(ip_hdr[12:16])
        dst = socket.inet_ntoa(ip_hdr[16:20])
        if src != dst_ip or dst != src_ip:
            continue
        ihl = (ip_hdr[0] & 0x0f) * 4
        tcp = data[ihl:ihl+20]
        sport, dport, seq, ack, off_flags = struct.unpack("!HHLLB", tcp[:13])[:5] if False else (None,)*5
        dport = struct.unpack("!H", tcp[0:2])[0]
        sport = struct.unpack("!H", tcp[2:4])[0]
        flags = tcp[13]
        if dport == src_port and sport == dst_port:
            if flags & 0x12 == 0x12:
                return "open"
            if flags & 0x04:
                return "closed"
            
    s.close()
    return "filtered"

def icmp_ping(dst_ip, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return None
    
    icmp_type = 8
    icmp_code = 0
    icmp_id = random.randrange(0, 65536)
    icmp_seq = 1
    payload = b"abcdefghijklmnopqrstuvwabcdefghi"
    header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_seq)
    s.sendto(header + payload, (dst_ip, 0))
    s.settimeout(timeout)
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            break
        if addr[0] == dst_ip:
            s.close()
            return True
    s.close()
    return False
         