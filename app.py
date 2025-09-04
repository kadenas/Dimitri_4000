import argparse
import csv
import os
import select
import socket
import time
import uuid
from datetime import datetime, UTC

# logging básico por si no existe logging_conf en tu repo
try:
    from logging_conf import setup_logging
    logger = setup_logging()
except Exception:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger("app")

from sip_manager import (
    SIPManager,
    build_options,
    parse_headers,
    status_from_response,
)


def write_csv_row(path, row, header=None):
    new_file = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new_file and header:
            w.writerow(header)
        w.writerow(row)


def parse_args():
    p = argparse.ArgumentParser(description="Dimitri 4000 - Monitor SIP OPTIONS")
    # CLI moderna
    p.add_argument("--dst", help="Host/IP destino SIP")
    p.add_argument("--dst-port", type=int, default=5060, help="Puerto SIP destino")
    p.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Transporte")
    p.add_argument("--interval", type=float, default=1.0, help="Intervalo entre envíos (s)")
    p.add_argument("--timeout", type=float, default=2.0, help="Timeout de socket (s)")
    p.add_argument("--count", type=int, default=1, help="Número de OPTIONS a enviar")
    p.add_argument("--bind-ip", default=None, help="IP local desde la que salir (opcional)")
    p.add_argument(
        "--src-port",
        type=int,
        default=0,
        help="Puerto UDP de origen (0 = efímero)",
    )
    p.add_argument("--cseq-start", type=int, default=1, help="CSeq inicial (por defecto 1)")
    p.add_argument("--service", action="store_true", help="Modo servicio continuo")
    p.add_argument(
        "--reply-options",
        action="store_true",
        help="Responder 200 OK a OPTIONS entrantes",
    )
    # Compatibilidad con la CLI antigua: host [port]
    p.add_argument("host", nargs="?", help="Destino (compat)")
    p.add_argument("port", nargs="?", type=int, help="Puerto destino (compat)")
    return p.parse_args()


def main():
    args = parse_args()

    if args.reply_options and not args.service:
        raise SystemExit("--reply-options requiere --service")

    dst = args.dst or args.host
    dport = args.dst_port if args.dst else (args.port or 5060)

    csv_path = "dimitri_stats.csv"
    header = ["ts_iso", "dst", "dst_port", "protocol", "status_code", "reason", "rtt_ms"]

    if args.service:
        if not dst and not args.reply_options:
            raise SystemExit("En modo servicio se requiere --dst o --reply-options")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(((args.bind_ip or "0.0.0.0"), args.src_port or 0))
        except OSError as e:
            logger.error(
                f"No se pudo bindear UDP en {args.bind_ip or '0.0.0.0'}:{args.src_port}: {e}"
            )
            raise SystemExit(1)

        local_port = sock.getsockname()[1]
        user = "dimitri"
        tag_local = uuid.uuid4().hex[:8]
        pending = []  # call_id -> send_time
        cseq = args.cseq_start
        next_send = time.time()

        try:
            while True:
                now = time.time()
                next_timeout = (
                    min(p["send_time"] + args.timeout for p in pending)
                    if pending
                    else None
                )
                wait_send = max(0, next_send - now) if dst else None
                wait_to = max(0, next_timeout - now) if next_timeout else None
                timeout = None
                if wait_send is not None and wait_to is not None:
                    timeout = min(wait_send, wait_to)
                elif wait_send is not None:
                    timeout = wait_send
                elif wait_to is not None:
                    timeout = wait_to

                r, _, _ = select.select([sock], [], [], timeout)
                now = time.time()

                if r:
                    data, addr = sock.recvfrom(4096)
                    if data.startswith(b"SIP/2.0"):
                        _, headers = parse_headers(data)
                        call_id = headers.get("call-id")
                        code, reason = status_from_response(data)
                        for p in list(pending):
                            if p["call_id"] == call_id:
                                rtt_ms = int((now - p["send_time"]) * 1000)
                                ts = datetime.now(UTC).isoformat()
                                write_csv_row(
                                    csv_path,
                                    [
                                        ts,
                                        p["dst"],
                                        p["dport"],
                                        args.protocol,
                                        code,
                                        reason,
                                        rtt_ms,
                                    ],
                                    header,
                                )
                                pending.remove(p)
                                break
                    elif data.startswith(b"OPTIONS sip:") and args.reply_options:
                        start, headers = parse_headers(data)
                        try:
                            via = headers["via"]
                            fr = headers["from"]
                            to = headers["to"]
                            call_id = headers["call-id"]
                            cseq_hdr = headers["cseq"]
                        except KeyError:
                            logger.debug(
                                "OPTIONS recibido incompleto de %s:%s", addr[0], addr[1]
                            )
                        else:
                            if "tag=" not in to.lower():
                                to = f"{to};tag={tag_local}"
                            if args.bind_ip:
                                contact_ip = args.bind_ip
                            else:
                                tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                try:
                                    tmp.connect(addr)
                                    contact_ip = tmp.getsockname()[0]
                                except OSError:
                                    contact_ip = sock.getsockname()[0]
                                finally:
                                    tmp.close()
                            resp = (
                                "SIP/2.0 200 OK\r\n"
                                f"Via: {via}\r\n"
                                f"From: {fr}\r\n"
                                f"To: {to}\r\n"
                                f"Call-ID: {call_id}\r\n"
                                f"CSeq: {cseq_hdr}\r\n"
                                f"Contact: <sip:{user}@{contact_ip}>\r\n"
                                "User-Agent: Dimitri-4000/0.1\r\n"
                                "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n"
                                "Accept: application/sdp\r\n"
                                "Content-Length: 0\r\n\r\n"
                            ).encode()
                            sock.sendto(resp, addr)
                            cseq_num = cseq_hdr.split()[0] if cseq_hdr else ""
                            logger.info(
                                f"Responded 200 OK to OPTIONS from {addr[0]}:{addr[1]} cid={call_id} cseq={cseq_num}"
                            )
                    else:
                        logger.debug(
                            "Datagrama ignorado de %s:%s", addr[0], addr[1]
                        )
                else:
                    for p in list(pending):
                        if now - p["send_time"] >= args.timeout:
                            ts = datetime.now(UTC).isoformat()
                            write_csv_row(
                                csv_path,
                                [
                                    ts,
                                    p["dst"],
                                    p["dport"],
                                    args.protocol,
                                    "",
                                    "timeout",
                                    "",
                                ],
                                header,
                            )
                            pending.remove(p)

                if dst and now >= next_send:
                    if args.bind_ip:
                        local_ip = args.bind_ip
                    else:
                        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        try:
                            tmp.connect((dst, dport))
                            local_ip = tmp.getsockname()[0]
                        except OSError:
                            local_ip = sock.getsockname()[0]
                        finally:
                            tmp.close()
                    call_id, payload = build_options(
                        dst, local_ip, local_port, user, cseq
                    )
                    logger.info(
                        f"Enviando OPTIONS (CSeq={cseq}) a {dst}:{dport} sent-by={local_ip}:{local_port}"
                    )
                    try:
                        sock.sendto(payload, (dst, dport))
                    except OSError as e:
                        logger.error(f"Error al enviar OPTIONS: {e}")
                    else:
                        pending.append(
                            {
                                "call_id": call_id,
                                "send_time": now,
                                "dst": dst,
                                "dport": dport,
                            }
                        )
                    cseq += 1
                    next_send = now + args.interval

        except KeyboardInterrupt:
            logger.info("Saliendo por Ctrl+C")
        finally:
            sock.close()

    else:
        if not dst:
            raise SystemExit(
                "Falta destino: usa --dst 10.0.0.1 o positional 'host'."
            )

        sm = SIPManager(protocol=args.protocol)
        ok = other = to = 0
        for i in range(args.count):
            cseq = args.cseq_start + i
            logger.info(f"Enviando OPTIONS (CSeq={cseq}) a {dst}:{dport}")
            try:
                code, reason, rtt_ms = sm.send_request(
                    dst_host=dst,
                    dst_port=dport,
                    timeout=args.timeout,
                    bind_ip=args.bind_ip,
                    bind_port=args.src_port,
                    cseq=cseq,
                )
            except OSError as e:
                logger.error(
                    f"No se pudo abrir socket UDP en puerto {args.src_port}: {e}"
                )
                raise SystemExit(1)

            ts = datetime.now(UTC).isoformat()
            if code is None:
                print(f"[{i+1}/{args.count}] Timeout")
                to += 1
                write_csv_row(
                    csv_path, [ts, dst, dport, args.protocol, "", "timeout", ""], header
                )
            else:
                print(f"[{i+1}/{args.count}] {code} {reason} {rtt_ms} ms")
                if code == 200:
                    ok += 1
                else:
                    other += 1
                write_csv_row(
                    csv_path,
                    [ts, dst, dport, args.protocol, code, reason, rtt_ms],
                    header,
                )

            if i + 1 < args.count:
                time.sleep(args.interval)

        print(f"Resumen: 200={ok} otros={other} timeouts={to}")


if __name__ == "__main__":
    main()
