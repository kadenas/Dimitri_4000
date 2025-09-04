import curses
import time
import app


def monitor(stdscr, host="127.0.0.1", port=5060, interval=5):
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    stdscr.nodelay(True)
    stdscr.timeout(100)

    monitoring = False
    success = failure = 0
    log = []
    last_latency = None
    last_ok = None
    next_time = 0

    while True:
        stdscr.erase()
        stdscr.addstr(0, 0, "SIP Monitor (m=start/stop, i=invite, q=quit)")
        state = "ON" if monitoring else "OFF"
        stdscr.addstr(2, 0, f"Monitoring: {state}")
        if last_ok is None:
            stdscr.addstr(3, 0, "Last OPTIONS: -")
        else:
            color = curses.color_pair(1 if last_ok else 2)
            status = "OK" if last_ok else "FAIL"
            stdscr.addstr(3, 0, f"Last OPTIONS: {status}", color)
        latency_text = f"{last_latency*1000:.1f} ms" if last_latency is not None else "-"
        stdscr.addstr(4, 0, f"Latency: {latency_text}")
        stdscr.addstr(5, 0, f"Success: {success}  Failure: {failure}")
        for idx, line in enumerate(log[-10:], start=7):
            stdscr.addstr(idx, 0, line)
        stdscr.refresh()

        now = time.time()
        if monitoring and now >= next_time:
            ok, latency, _, _ = app.send_options(host, port)
            last_ok = ok
            last_latency = latency
            msg = f"OPTIONS {'OK' if ok else 'FAIL'} {latency*1000:.1f}ms"
            log.append(msg)
            if ok:
                success += 1
            else:
                failure += 1
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
            headers = "".join(f"{h.strip()}\r\n" for h in headers_line.split(';') if h.strip())
            ok, latency, _, _ = app.send_invite(host, port, headers=headers)
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
