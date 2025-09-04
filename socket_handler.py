import socket
import ipaddress
from contextlib import contextmanager
from typing import Generator, Tuple


def _validate_ip(ip: str) -> None:
    """Raise ValueError if *ip* is not a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"IP inválida: {ip}") from exc


@contextmanager
def open_udp_socket(
    remote_ip: str,
    remote_port: int,
    local_port: int = 0,
    timeout: float | None = None,
) -> Generator[Tuple[socket.socket, Tuple[str, int]], None, None]:
    """Context manager that yields a UDP socket and remote address tuple.

    The socket is bound to *local_port* and closed automatically when the
    context exits. *timeout* may be specified in seconds. The remote IP is
    validated before the socket is created.
    """
    _validate_ip(remote_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.bind(("", local_port))
        yield sock, (remote_ip, remote_port)
    finally:
        sock.close()


def udp_send(sock: socket.socket, data: bytes, addr: Tuple[str, int]) -> None:
    """Send *data* through *sock* to the provided remote *addr*."""
    sock.sendto(data, addr)


def udp_receive(sock: socket.socket, bufsize: int = 1024) -> Tuple[bytes, Tuple[str, int]]:
    """Receive data from *sock*. Returns a tuple of (data, address)."""
    return sock.recvfrom(bufsize)


@contextmanager
def open_tcp_socket(
    remote_ip: str,
    remote_port: int,
    local_port: int = 0,
    timeout: float | None = None,
) -> Generator[socket.socket, None, None]:
    """Context manager that yields a connected TCP socket.

    The socket is bound to *local_port* and closed automatically when the
    context exits. *timeout* may be specified in seconds. The remote IP is
    validated before the connection attempt.
    """
    _validate_ip(remote_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.bind(("", local_port))
        sock.connect((remote_ip, remote_port))
        yield sock
    finally:
        sock.close()


def tcp_send(sock: socket.socket, data: bytes) -> None:
    """Send *data* through the TCP *sock*."""
    sock.sendall(data)


def tcp_receive(sock: socket.socket, bufsize: int = 1024) -> bytes:
    """Receive data from the TCP *sock*."""
    return sock.recv(bufsize)
