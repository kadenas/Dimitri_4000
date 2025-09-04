import argparse
import csv
import os
import time
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

from sip_manager import SIPManager


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
    p.add_argument("--cseq-start", type=int, default=1, help="CSeq inicial (por defecto 1)")
    # Compatibilidad con la CLI antigua: host [port]
    p.add_argument("host", nargs="?", help="Destino (compat)")
    p.add_argument("port", nargs="?", type=int, help="Puerto destino (compat)")
    return p.parse_args()


def main():
    args = parse_args()

    dst = args.dst or args.host
    if not dst:
        raise SystemExit("Falta destino: usa --dst 10.0.0.1 o positional 'host'.")

    dport = args.dst_port if args.dst else (args.port or 5060)

    sm = SIPManager(protocol=args.protocol)

    ok = other = to = 0
    csv_path = "dimitri_stats.csv"
    header = ["ts_iso", "dst", "dst_port", "protocol", "status_code", "reason", "rtt_ms"]

    for i in range(args.count):
        cseq = args.cseq_start + i
        logger.info(f"Enviando OPTIONS (CSeq={cseq}) a {dst}:{dport}")
        code, reason, rtt_ms = sm.send_request(
            dst_host=dst,
            dst_port=dport,
            timeout=args.timeout,
            bind_ip=args.bind_ip,
            cseq=cseq,
        )

        ts = datetime.now(UTC).isoformat()
        if code is None:
            print(f"[{i+1}/{args.count}] Timeout")
            to += 1
            write_csv_row(csv_path, [ts, dst, dport, args.protocol, "", "timeout", ""])
        else:
            print(f"[{i+1}/{args.count}] {code} {reason} {rtt_ms} ms")
            if code == 200:
                ok += 1
            else:
                other += 1
            write_csv_row(csv_path, [ts, dst, dport, args.protocol, code, reason, rtt_ms])

        if i + 1 < args.count:
            time.sleep(args.interval)

    print(f"Resumen: 200={ok} otros={other} timeouts={to}")


if __name__ == "__main__":
    main()