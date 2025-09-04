import socket, sys, uuid, time
import logging

from logging_conf import setup_logging


logger = setup_logging()

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
    start = time.time()
    msg = build_options(dst_host, dst_port)
    logger.info("Enviando OPTIONS a %s:%s", dst_host, dst_port)
    logger.debug("Mensaje enviado: %s", msg.decode(errors="ignore"))
    s.sendto(msg, (dst_host, dst_port))
    try:
        data, addr = s.recvfrom(2048)
        latency = time.time() - start
        logger.info("Respuesta de %s:%s", addr[0], addr[1])
        logger.debug("Mensaje recibido: %s", data.decode(errors="ignore"))
        return True, latency, addr, data.decode(errors="ignore")
    except socket.timeout:
        latency = time.time() - start
        logger.error("Timeout esperando respuesta de %s:%s", dst_host, dst_port)
        return False, latency, None, ""
    except OSError as exc:
        latency = time.time() - start
        logger.error("Error de red enviando OPTIONS: %s", exc)
        return False, latency, None, ""
    finally:
        s.close()


def build_invite(dst_host, dst_port, src_host="127.0.0.1", user="dimitri", headers=""):
    if headers and not headers.endswith("\r\n"):
        headers += "\r\n"
    call_id = str(uuid.uuid4())
    branch = "z9hG4bK" + call_id.replace("-", "")
    msg = (
        f"INVITE sip:{dst_host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {src_host}:5060;branch={branch}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{user}@{src_host}>;tag={user}\r\n"
        f"To: <sip:{dst_host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"{headers}"
        f"Contact: <sip:{user}@{src_host}:5060>\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def send_invite(dst_host, dst_port=5060, timeout=2, headers=""):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", 5060))
    start = time.time()
    msg = build_invite(dst_host, dst_port, headers=headers)
    logger.info("Enviando INVITE a %s:%s", dst_host, dst_port)
    logger.debug("Mensaje enviado: %s", msg.decode(errors="ignore"))
    s.sendto(msg, (dst_host, dst_port))
    try:
        data, addr = s.recvfrom(2048)
        latency = time.time() - start
        logger.info("Respuesta de %s:%s", addr[0], addr[1])
        logger.debug("Mensaje recibido: %s", data.decode(errors="ignore"))
        return True, latency, addr, data.decode(errors="ignore")
    except socket.timeout:
        latency = time.time() - start
        logger.error("Timeout esperando respuesta de %s:%s", dst_host, dst_port)
        return False, latency, None, ""
    except OSError as exc:
        latency = time.time() - start
        logger.error("Error de red enviando INVITE: %s", exc)
        return False, latency, None, ""
    finally:
        s.close()
if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
    ok, latency, addr, data = send_options(host, port)
    if ok:
        logger.info("Respuesta de %s:%s", addr[0], addr[1])
        print("Respuesta de", addr, "\n", data)
    else:
        logger.error("Timeout esperando respuesta de %s:%s", host, port)
        print("Timeout esperando respuesta")