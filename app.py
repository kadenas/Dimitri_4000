import socket, sys, uuid, time

def build_options(dst_host, dst_port, src_host="127.0.0.1", user="dimitri"):
    call_id = str(uuid.uuid4())
    branch = "z9hG4bK" + call_id.replace("-", "")
    msg = (
        f"OPTIONS sip:{dst_host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {src_host}:5060;branch={branch}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{user}@{src_host}>;tag={user}\r\n"
        f"To: <sip:{dst_host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:{user}@{src_host}:5060>\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return msg.encode()
def send_options(dst_host, dst_port=5060, timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", 5060))
    s.sendto(build_options(dst_host, dst_port), (dst_host, dst_port))
    try:
        data, addr = s.recvfrom(2048)
        print("Respuesta de", addr, "\n", data.decode(errors="ignore"))
    except socket.timeout:
        print("Timeout esperando respuesta")
    finally:
        s.close()
if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
    send_options(host, port)
