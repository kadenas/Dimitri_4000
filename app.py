import sys
from sip_manager import SIPManager


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
    protocol = sys.argv[3] if len(sys.argv) > 3 else "UDP"
    interval = float(sys.argv[4]) if len(sys.argv) > 4 else 60
    timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 2

    manager = SIPManager(
        remote_ip=host,
        remote_port=port,
        protocol=protocol,
        interval=interval,
        timeout=timeout,
    )

    response = manager.send_request("OPTIONS")
    if response:
        print("Respuesta de", response["from"])
        print(response["raw"])
    else:
        print("Timeout esperando respuesta")
