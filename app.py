
import argparse
import csv
import os
import socket
import sys
import time
import uuid
from datetime import datetime

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


def append_csv(filename, row):
    exists = os.path.isfile(filename)
    with open(filename, "a", newline="") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(["ts_iso", "dst", "dst_port", "protocol", "status_code", "reason", "rtt_ms"])
        writer.writerow(row)


def run_monitor(manager, count, interval):
    ok = other = to = 0
    total = count
    label = str(total) if total else "∞"
    i = 0
    try:
        while total == 0 or i < total:
            i += 1
            start = datetime.utcnow().isoformat()
            status, reason, rtt, _ = manager.send_options()
            append_csv(
                "dimitri_stats.csv",
                [start, manager.remote_ip, manager.remote_port, manager.protocol.lower(), status or "", reason, f"{rtt:.3f}"],
            )
            if status is None:
                print(f"[{i}/{label}] Timeout")
                to += 1
            elif status == 200:
                print(f"[{i}/{label}] 200 OK {rtt:.0f} ms")
                ok += 1
            else:
                print(f"[{i}/{label}] {status} {reason} {rtt:.0f} ms")
                other += 1
            if total == 0 or i < total:
                time.sleep(interval)
    except KeyboardInterrupt:
        pass
    print(f"Resumen: 200={ok} otros={other} timeouts={to}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Envía mensajes SIP OPTIONS")
    parser.add_argument("host", nargs="?", help="Host remoto si no se usa config")
    parser.add_argument("port", nargs="?", type=int, help="Puerto remoto", default=5060)
    parser.add_argument("-c", "--config", help="Archivo de configuración")
    parser.add_argument("-n", "--name", help="Nombre del destino en la config")
    parser.add_argument("--dst", help="Host destino")
    parser.add_argument("--dst-port", type=int, default=5060, help="Puerto destino")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--count", type=int, default=1, help="Número de OPTIONS a enviar (0=infinito)")
    parser.add_argument("--bind-ip", help="IP de origen")
    args = parser.parse_args()

    if args.protocol.lower() == "tcp":
        print("TCP no implementado")
        sys.exit(1)

    if args.config and args.name:
        destinations = load_config(args.config)
        if args.name not in destinations:
            parser.error(f"Destino {args.name} no encontrado en config")
        dst = destinations[args.name]
        manager = SIPManager(
            dst.ip,
            args.dst_port if args.dst_port else dst.port,
            protocol=args.protocol,
            interval=args.interval if args.interval else dst.interval,
            timeout=args.timeout if args.timeout else dst.timeout,
            src_ip=args.bind_ip or "0.0.0.0",
        )
        run_monitor(manager, args.count, manager.interval)
    else:
        host = args.dst or args.host or "127.0.0.1"
        port = args.port if args.port is not None else args.dst_port
        manager = SIPManager(
            host,
            port,
            protocol=args.protocol,
            interval=args.interval,
            timeout=args.timeout,
            src_ip=args.bind_ip or "0.0.0.0",
        )
        run_monitor(manager, args.count, args.interval)
