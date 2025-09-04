import socket, sys, uuid, time
import logging
import argparse

from logging_conf import setup_logging
from config import load_config
from sip_manager import SIPManager


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
    parser = argparse.ArgumentParser(description="Envía mensajes SIP OPTIONS")
    parser.add_argument("host", nargs="?", help="Host remoto si no se usa config")
    parser.add_argument("port", nargs="?", type=int, help="Puerto remoto", default=5060)
    parser.add_argument("-c", "--config", help="Archivo de configuración")
    parser.add_argument("-n", "--name", help="Nombre del destino en la config")
    parser.add_argument("--port", dest="override_port", type=int, help="Puerto alternativo")
    parser.add_argument("--count", type=int, default=1, help="Número de OPTIONS a enviar (0=infinito)")
    args = parser.parse_args()

    if args.config and args.name:
        destinations = load_config(args.config)
        if args.name not in destinations:
            parser.error(f"Destino {args.name} no encontrado en config")
        dst = destinations[args.name]
        if args.override_port is not None:
            dst.port = args.override_port
        manager = SIPManager(dst.ip, dst.port, protocol=dst.protocol, interval=dst.interval)
        repeat = None if args.count == 0 else args.count
        manager.send_request("OPTIONS", repeat=repeat)
    else:
        host = args.host if args.host else "127.0.0.1"
        port = args.override_port if args.override_port is not None else args.port
        ok, latency, addr, data = send_options(host, port)
        if ok:
            logger.info("Respuesta de %s:%s", addr[0], addr[1])
            print("Respuesta de", addr, "\n", data)
        else:
            logger.error("Timeout esperando respuesta de %s:%s", host, port)
            print("Timeout esperando respuesta")
