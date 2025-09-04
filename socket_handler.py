import socket
import ipaddress
import logging
from contextlib import contextmanager
from typing import Generator, Tuple

from logging_conf import setup_logging


setup_logging()
logger = logging.getLogger(__name__)


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
    logger.info("Abriendo socket UDP a %s:%s", remote_ip, remote_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.bind(("", local_port))
        yield sock, (remote_ip, remote_port)
    except OSError as exc:
        logger.error("Error de red en socket UDP: %s", exc)
        raise
    finally:
        sock.close()
        logger.info("Socket UDP cerrado")


def udp_send(sock: socket.socket, data: bytes, addr: Tuple[str, int]) -> None:
    """Send *data* through *sock* to the provided remote *addr*."""
    try:
        sock.sendto(data, addr)
        logger.info("UDP enviado a %s:%s", addr[0], addr[1])
        logger.debug("Mensaje enviado: %s", data.decode(errors="ignore"))
    except OSError as exc:
        logger.error("Error de red enviando UDP a %s:%s - %s", addr[0], addr[1], exc)
        raise


def udp_receive(sock: socket.socket, bufsize: int = 1024) -> Tuple[bytes, Tuple[str, int]]:
    """Receive data from *sock*. Returns a tuple of (data, address)."""
    try:
        data, addr = sock.recvfrom(bufsize)
        logger.info("UDP recibido de %s:%s", addr[0], addr[1])
        logger.debug("Mensaje recibido: %s", data.decode(errors="ignore"))
        return data, addr
    except OSError as exc:
        logger.error("Error de red recibiendo UDP: %s", exc)
        raise


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
    logger.info("Abriendo socket TCP a %s:%s", remote_ip, remote_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.bind(("", local_port))
        sock.connect((remote_ip, remote_port))
        yield sock
    except OSError as exc:
        logger.error("Error de red en socket TCP: %s", exc)
        raise
    finally:
        sock.close()
        logger.info("Socket TCP cerrado")


def tcp_send(sock: socket.socket, data: bytes) -> None:
    """Send *data* through the TCP *sock*."""
    try:
        sock.sendall(data)
        peer = sock.getpeername()
        logger.info("TCP enviado a %s:%s", peer[0], peer[1])
        logger.debug("Mensaje enviado: %s", data.decode(errors="ignore"))
    except OSError as exc:
        logger.error("Error de red enviando TCP: %s", exc)
        raise


def tcp_receive(sock: socket.socket, bufsize: int = 1024) -> bytes:
    """Receive data from the TCP *sock*."""
    try:
        data = sock.recv(bufsize)
        peer = sock.getpeername()
        logger.info("TCP recibido de %s:%s", peer[0], peer[1])
        logger.debug("Mensaje recibido: %s", data.decode(errors="ignore"))
        return data
    except OSError as exc:
        logger.error("Error de red recibiendo TCP: %s", exc)
        raise
