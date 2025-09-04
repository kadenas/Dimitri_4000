import curses
import time
from sip_manager import SIPManager


def monitor(stdscr, host="127.0.0.1", port=5060, interval=5):
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    stdscr.nodelay(True)
    stdscr.timeout(100)

    manager = SIPManager(host, port, interval=interval)
    monitoring = False
    log = []
    next_time = 0

    while True:
        stdscr.erase()
        stdscr.addstr(0, 0, "SIP Monitor (m=start/stop, i=invite, q=quit)")
        state = "ON" if monitoring else "OFF"
        stdscr.addstr(2, 0, f"Monitoring: {state}")
        opt = manager.get_stats("OPTIONS")
        inv = manager.get_stats("INVITE")
        stdscr.addstr(3, 0, (
            f"OPTIONS: sent {opt['sent']} 200OK {opt['ok']} timeout {opt['timeout']} "
            f"success {opt['success_rate']*100:.1f}% avg {opt['avg_latency']*1000:.1f}ms"
        ))
        stdscr.addstr(4, 0, (
            f"INVITE: sent {inv['sent']} 200OK {inv['ok']} timeout {inv['timeout']} "
            f"success {inv['success_rate']*100:.1f}% avg {inv['avg_latency']*1000:.1f}ms"
        ))
        for idx, line in enumerate(log[-10:], start=6):
            stdscr.addstr(idx, 0, line)
        stdscr.refresh()

        now = time.time()
        if monitoring and now >= next_time:
            resp, latency = manager.send_request("OPTIONS")
            ok = resp is not None and resp.get("status") == 200
            msg = f"OPTIONS {'OK' if ok else 'FAIL'} {latency*1000:.1f}ms"
            log.append(msg)
            next_time = now + interval

        c = stdscr.getch()
        if c == ord('q'):
            break
        elif c == ord('m'):
            monitoring = not monitoring
            if monitoring:
                next_time = 0
        elif c == ord('i'):
            curses.echo()
            stdscr.addstr(18, 0, "Headers (key:value;...): ")
            headers_line = stdscr.getstr(18, 26).decode()
            curses.noecho()
            headers = "".join(
                f"{h.strip()}\r\n" for h in headers_line.split(';') if h.strip()
            )
            resp, latency = manager.send_request("INVITE", headers=headers)
            ok = resp is not None and resp.get("status") == 200
            msg = f"INVITE {'OK' if ok else 'FAIL'} {latency*1000:.1f}ms"
            log.append(msg)
        time.sleep(0.1)


def main():
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
    curses.wrapper(lambda stdscr: monitor(stdscr, host, port))


if __name__ == "__main__":
    main()
