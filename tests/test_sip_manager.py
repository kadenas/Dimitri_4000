import socket
from contextlib import contextmanager
from pathlib import Path
import sys

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))
from sip_manager import SIPManager


@contextmanager
def dummy_udp_socket(remote_ip, remote_port, *args, **kwargs):
    """Yield a dummy socket and the provided remote address."""
    yield object(), (remote_ip, remote_port)


def test_build_options_message():
    manager = SIPManager("198.51.100.10", user="alice")
    msg = manager.build_options()
    assert msg.startswith("OPTIONS sip:198.51.100.10 SIP/2.0")
    assert "Content-Length: 0" in msg
    assert "Via: SIP/2.0/UDP" in msg


def test_build_invite_with_custom_headers():
    manager = SIPManager("198.51.100.10", user="alice")
    msg = manager.build_invite({"User-Agent": "pytest"})
    assert "INVITE sip:198.51.100.10 SIP/2.0" in msg
    assert "User-Agent: pytest" in msg
    assert "Content-Length: 0" in msg
    # mandatory header
    assert "Via: SIP/2.0/UDP" in msg


def test_send_request_parses_response(monkeypatch):
    manager = SIPManager("198.51.100.10")

    monkeypatch.setattr("sip_manager.open_udp_socket", dummy_udp_socket)

    sent_messages = []

    def fake_send(sock, data, addr):
        sent_messages.append(data)

    def fake_recv(sock):
        return b"SIP/2.0 200 OK\r\n\r\n", ("198.51.100.10", 5060)

    monkeypatch.setattr("sip_manager.udp_send", fake_send)
    monkeypatch.setattr("sip_manager.udp_receive", fake_recv)

    response, latency = manager.send_request(method="INVITE")
    assert response["status"] == 200
    assert response["reason"] == "OK"
    assert sent_messages, "Expected message to be sent"
    stats = manager.get_stats("INVITE")
    assert stats["sent"] == 1
    assert stats["ok"] == 1
    assert stats["timeout"] == 0


def test_send_request_timeout(monkeypatch):
    manager = SIPManager("198.51.100.10", timeout=0.1)

    monkeypatch.setattr("sip_manager.open_udp_socket", dummy_udp_socket)

    def fake_send(sock, data, addr):
        pass

    def fake_recv(sock):
        raise socket.timeout

    monkeypatch.setattr("sip_manager.udp_send", fake_send)
    monkeypatch.setattr("sip_manager.udp_receive", fake_recv)

    response, latency = manager.send_request(method="OPTIONS", retries=1)
    assert response is None
    stats = manager.get_stats("OPTIONS")
    assert stats["sent"] == 1
    assert stats["timeout"] == 1
