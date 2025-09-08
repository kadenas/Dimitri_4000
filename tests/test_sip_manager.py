from pathlib import Path
import sys
import hashlib

sys.path.append(str(Path(__file__).resolve().parents[1]))

import pytest

from sip_manager import (
    build_options,
    build_response,
    build_sdp,
    build_bye,
    build_bye_request,
    parse_headers,
    status_from_response,
    normalize_number,
    make_uri,
    build_invite,
    parse_auth,
    build_digest_auth,
    _route_set_from_record_route,
)


def test_status_from_response_parses_code_and_reason():
    data = b"SIP/2.0 486 Busy Here\r\n\r\n"
    code, reason = status_from_response(data)
    assert code == 486
    assert reason == "Busy Here"


def test_parse_headers_extracts_fields():
    msg = (
        b"SIP/2.0 200 OK\r\n"
        b"Contact: <sip:alice@10.0.0.1>\r\n"
        b"To: <sip:bob@10.0.0.2>;tag=abc\r\n\r\n"
    )
    start, headers = parse_headers(msg)
    assert start.startswith("SIP/2.0 200")
    assert headers["contact"].startswith("<sip:alice@")
    assert headers["to"].endswith("tag=abc")


def test_build_options_contains_mandatory_headers():
    call_id, payload = build_options("example.com", "10.0.0.1", 5070, "alice", 1)
    text = payload.decode()
    assert "OPTIONS sip:example.com SIP/2.0" in text
    assert f"Call-ID: {call_id}" in text
    assert "Content-Length: 0" in text


def test_build_response_generates_basic_sip_message():
    resp = build_response(200, "OK", {"Via": "v1", "To": "<sip:b@1>"})
    text = resp.decode()
    assert text.startswith("SIP/2.0 200 OK")
    assert "Via: v1" in text
    assert "Content-Length: 0" in text


def test_build_sdp_returns_valid_structure():
    sdp = build_sdp("10.0.0.1", 4000, 0)
    assert "c=IN IP4 10.0.0.1" in sdp
    assert "m=audio 4000 RTP/AVP" in sdp


def test_build_bye_uses_dialog_fields():
    dialog = {
        "peer_uri": "sip:alice@10.0.0.1",
        "from_uri": "<sip:alice@10.0.0.1>;tag=rtag",
        "to_uri": "<sip:bob@10.0.0.2>",
        "local_tag": "ltag",
        "call_id": "cid",
        "our_next_cseq": 1,
        "local_ip": "10.0.0.2",
        "local_port": 5060,
    }
    msg = build_bye(dialog)
    text = msg.decode()
    assert "BYE sip:alice@10.0.0.1 SIP/2.0" in text
    assert "CSeq: 1 BYE" in text
    assert "From: <sip:bob@10.0.0.2>;tag=ltag" in text


def test_build_bye_request_includes_route_set():
    bye = build_bye_request(
        "sip:bob@10.0.0.1",
        "<sip:bob@10.0.0.1>;tag=abc",
        "10.0.0.2",
        5060,
        "sip:alice@10.0.0.2",
        None,
        "cid",
        2,
        "ltag",
        "+1000",
        route_set=["<sip:proxy1;lr>", "<sip:proxy2>"]
    )
    text = bye.decode()
    assert "Route: <sip:proxy1;lr>" in text
    assert "Route: <sip:proxy2>" in text
    assert text.index("Route: <sip:proxy1;lr>") < text.index("Route: <sip:proxy2>")


def test_normalize_number_and_make_uri():
    assert normalize_number(" +34 987-123-456 ") == "+34987123456"
    with pytest.raises(ValueError):
        normalize_number("abc123")
    assert make_uri("alice", "example.com") == "sip:alice@example.com"


def test_route_set_from_record_route_reverses_order():
    rr = "<sip:proxy1;lr>, <sip:proxy2>"
    rs = _route_set_from_record_route(rr)
    assert rs == ["<sip:proxy2>", "<sip:proxy1;lr>"]


def test_build_invite_includes_pai_and_display():
    sdp = "v=0\r\n"
    msg = build_invite(
        "sip:123@1.1.1.1",
        "sip:+1000@a.com",
        "sip:+2000@b.com",
        "10.0.0.1",
        5060,
        "cid",
        1,
        "t",
        "b",
        sdp,
        from_display="Tester",
        contact_user="+1000",
        pai="sip:+1000@c.com",
        use_pai=True,
        use_pai_asserted=True,
    )
    text = msg.decode()
    assert 'INVITE sip:123@1.1.1.1 SIP/2.0' in text
    assert 'From: "Tester" <sip:+1000@a.com>;tag=t' in text
    assert 'To: <sip:+2000@b.com>' in text
    assert 'P-Preferred-Identity: <sip:+1000@c.com>' in text
    assert 'P-Asserted-Identity: <sip:+1000@c.com>' in text


def test_parse_auth_and_build_digest_auth():
    ch = 'Digest realm="test", nonce="abc", algorithm=MD5, qop="auth", opaque="xyz"'
    params = parse_auth(ch)
    assert params["realm"] == "test"
    assert params["nonce"] == "abc"
    assert params["algorithm"].upper() == "MD5"
    assert params["qop"] == "auth"
    assert params["opaque"] == "xyz"
    expected_resp = hashlib.md5(
        (
            hashlib.md5("u:test:pass".encode()).hexdigest()
            + ":abc:00000001:deadbeef:auth:" + hashlib.md5("INVITE:sip:x".encode()).hexdigest()
        ).encode()
    ).hexdigest()
    auth_val = build_digest_auth(
        "INVITE",
        "sip:x",
        "u",
        "pass",
        "test",
        "abc",
        "auth",
        "deadbeef",
        1,
        opaque="xyz",
    )
    assert f'response="{expected_resp}"' in auth_val
