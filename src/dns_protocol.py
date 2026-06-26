"""dns_protocol.py — Formato simplificado de mensagem DNS (Mini-DNS).

QUERY (pergunta):
    - id          : 2 bytes (uint16) — identificador da transação
    - qtype       : 1 byte  (0x01 = tipo A / IPv4)
    - name_len    : 1 byte  — comprimento do nome de domínio
    - name        : name_len bytes (ASCII, ex: "webserver.ufpi.local")

RESPONSE (resposta):
    - id          : 2 bytes (uint16) — mesmo ID da query (correlaciona req/resp)
    - rcode       : 1 byte  (0x00 = NOERROR / encontrado, 0x03 = NXDOMAIN / não encontrado)
    - name_len    : 1 byte
    - name        : name_len bytes
    - ip          : 4 bytes (apenas se rcode == 0x00) — endereço IPv4 em binário
"""

import socket
import struct

DNS_PORT_DEFAULT = 53  # porta "real" do DNS; em containers sem root usamos 5300 (custom)

QTYPE_A = 0x01

RCODE_NOERROR = 0x00
RCODE_NXDOMAIN = 0x03

_QUERY_HEADER = struct.Struct("!HBB")     # id, qtype, name_len
_RESP_HEADER_OK = struct.Struct("!HBB")   # id, rcode, name_len  (+ name + ip depois)


def build_query(transaction_id: int, name: str, qtype: int = QTYPE_A) -> bytes:
    name_bytes = name.encode("ascii")
    header = _QUERY_HEADER.pack(transaction_id, qtype, len(name_bytes))
    return header + name_bytes


def parse_query(raw: bytes) -> dict | None:
    if len(raw) < _QUERY_HEADER.size:
        return None
    try:
        transaction_id, qtype, name_len = _QUERY_HEADER.unpack(raw[:_QUERY_HEADER.size])
        name = raw[_QUERY_HEADER.size: _QUERY_HEADER.size + name_len].decode("ascii")
        return {"id": transaction_id, "qtype": qtype, "name": name}
    except Exception:
        return None


def build_response(transaction_id: int, name: str, ip: str | None,
                    rcode: int = RCODE_NOERROR) -> bytes:
    name_bytes = name.encode("ascii")
    header = _RESP_HEADER_OK.pack(transaction_id, rcode, len(name_bytes))
    body = header + name_bytes
    if rcode == RCODE_NOERROR and ip:
        body += socket.inet_aton(ip)
    return body


def parse_response(raw: bytes) -> dict | None:
    if len(raw) < _RESP_HEADER_OK.size:
        return None
    try:
        transaction_id, rcode, name_len = _RESP_HEADER_OK.unpack(raw[:_RESP_HEADER_OK.size])
        offset = _RESP_HEADER_OK.size
        name = raw[offset: offset + name_len].decode("ascii")
        offset += name_len
        ip = None
        if rcode == RCODE_NOERROR:
            ip_bytes = raw[offset: offset + 4]
            if len(ip_bytes) == 4:
                ip = socket.inet_ntoa(ip_bytes)
        return {"id": transaction_id, "rcode": rcode, "name": name, "ip": ip}
    except Exception:
        return None


def rcode_str(rcode: int) -> str:
    return {RCODE_NOERROR: "NOERROR", RCODE_NXDOMAIN: "NXDOMAIN"}.get(rcode, f"0x{rcode:02x}")
