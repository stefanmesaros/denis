#!/usr/bin/env python3
"""Write a small Ethernet pcap of *encrypted* industrial traffic, for `denis replay`: real TLS handshakes (made by
OpenSSL through Python's ssl module over memory buffers, so the bytes are what a real client and server send) between
an HMI, a laptop and a PLC on 192.168.1.0/24.

    python3 tools/make-encrypted-sample.py out.pcap

The HMI talks secured OPC UA (TCP 4843) to the PLC, the laptop opens a TLS session to the same PLC on 8443, and two
office machines talk TLS to each other (which DENIS must ignore). Needs the `openssl` command for a throw-away certificate.
"""
import socket, ssl, struct, subprocess, sys, tempfile, os

def handshake(version):
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d + "/k.pem", "-out", d + "/c.pem", "-days", "2", "-subj", "/CN=plc1.plant.local"], check=True, capture_output=True)
    sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sc.load_cert_chain(d + "/c.pem", d + "/k.pem")
    cc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cc.check_hostname = False; cc.verify_mode = ssl.CERT_NONE
    for c in (sc, cc):
        c.minimum_version = c.maximum_version = version
    ci, co, si, so = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c = cc.wrap_bio(ci, co, server_hostname="plc1.plant.local"); s = sc.wrap_bio(si, so, server_side=True)
    flights = []  # (from_client, bytes)
    for _ in range(6):
        for obj, out_bio, in_bio, from_client in ((c, co, si, True), (s, so, ci, False)):
            try: obj.do_handshake()
            except ssl.SSLWantReadError: pass
            data = out_bio.read()
            if data:
                flights.append((from_client, data)); in_bio.write(data)
    return flights

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff

def frame(smac, dmac, sip, dip, sport, dport, payload, seq):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, socket.inet_aton(sip), socket.inet_aton(dip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return bytes.fromhex(dmac.replace(":", "")) + bytes.fromhex(smac.replace(":", "")) + b"\x08\x00" + ip + tcp

HMI = ("00:1b:63:00:00:01", "192.168.1.30"); PLC = ("00:1b:1b:00:00:02", "192.168.1.31")
LAPTOP = ("3c:22:fb:00:00:03", "192.168.1.32"); PC1 = ("3c:22:fb:00:00:04", "192.168.1.40"); PC2 = ("3c:22:fb:00:00:05", "192.168.1.41")
out = []
t = 1_700_000_000
def session(client, server, sport, dport, version):
    global t
    for from_client, data in handshake(version):
        a, b = (client, server) if from_client else (server, client)
        sp, dp = (sport, dport) if from_client else (dport, sport)
        for i in range(0, len(data), 1400):
            out.append((t, frame(a[0], b[0], a[1], b[1], sp, dp, data[i:i + 1400], 1000 + i)))
        t += 1
    for _ in range(3):  # a few encrypted application-data records each way
        out.append((t, frame(client[0], server[0], client[1], server[1], sport, dport, b"\x17\x03\x03\x00\x20" + os.urandom(32), 9000))); t += 1
        out.append((t, frame(server[0], client[0], server[1], client[1], dport, sport, b"\x17\x03\x03\x00\x20" + os.urandom(32), 9000))); t += 1
session(HMI, PLC, 50001, 4843, ssl.TLSVersion.TLSv1_3)
session(LAPTOP, PLC, 50002, 8443, ssl.TLSVersion.TLSv1_2)
session(PC1, PC2, 50003, 443, ssl.TLSVersion.TLSv1_3)
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, pkt in out:
        f.write(struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt)
print(f"wrote {sys.argv[1]}: {len(out)} packets")
