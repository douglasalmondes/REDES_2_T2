"""http_common.py — Utilitários HTTP/1.1 simplificados, compartilhados entre
o transporte TCP nativo e o transporte R-UDP.

O miniservidor entende apenas requisições GET. Cada resposta inclui os
cabeçalhos:
    HTTP/1.1 200 OK | 404 Not Found
    Content-Type
    Content-Length
    X-Custom-Auth     (Matrícula + Nome)
"""

import mimetypes
import os

from protocol import X_CUSTOM_AUTH

HTTP_VERSION = "HTTP/1.1"

REASON_PHRASES = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
}


def guess_content_type(path: str) -> str:
    ctype, _ = mimetypes.guess_type(path)
    return ctype or "application/octet-stream"


def build_request(method: str, path: str, host: str) -> bytes:
    """Monta uma requisição HTTP/1.1 simplificada (texto puro)."""
    lines = [
        f"{method} {path} {HTTP_VERSION}",
        f"Host: {host}",
        f"X-Custom-Auth: {X_CUSTOM_AUTH}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def parse_request(raw: bytes) -> dict | None:
    """Parseia uma requisição HTTP simplificada (apenas a request-line e headers)."""
    try:
        text = raw.decode("utf-8", errors="replace")
        head = text.split("\r\n\r\n", 1)[0]
        lines = head.split("\r\n")
        if not lines:
            return None

        request_line = lines[0].split()
        if len(request_line) != 3:
            return None
        method, path, version = request_line

        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

        return {"method": method, "path": path, "version": version, "headers": headers}
    except Exception:
        return None


def build_response(status: int, content_type: str, body: bytes,
                    extra_headers: dict | None = None) -> bytes:
    """Monta a resposta HTTP/1.1 completa (headers + corpo) como bytes."""
    reason = REASON_PHRASES.get(status, "Unknown")
    headers = [
        f"{HTTP_VERSION} {status} {reason}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        f"X-Custom-Auth: {X_CUSTOM_AUTH}",
        "Connection: close",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            headers.append(f"{k}: {v}")
    header_blob = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")
    return header_blob + body


def parse_response_head(raw: bytes) -> dict | None:
    """Parseia status-line + headers de uma resposta HTTP. Não exige o corpo completo."""
    try:
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            return None
        head = raw[:sep].decode("utf-8", errors="replace")
        body_start = sep + 4

        lines = head.split("\r\n")
        status_line = lines[0].split(maxsplit=2)
        if len(status_line) < 2:
            return None
        version = status_line[0]
        status = int(status_line[1])
        reason = status_line[2] if len(status_line) > 2 else ""

        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

        return {
            "version": version,
            "status": status,
            "reason": reason,
            "headers": headers,
            "body_start": body_start,
        }
    except Exception:
        return None


def resolve_static_path(www_root: str, url_path: str) -> str:
    """Mapeia o path da URL para um caminho de arquivo dentro de www_root,
    impedindo path traversal (ex: '/../etc/passwd')."""
    if url_path == "/" or url_path == "":
        url_path = "/index.html"
    safe_path = os.path.normpath(url_path).lstrip("/")
    full_path = os.path.normpath(os.path.join(www_root, safe_path))

    if not full_path.startswith(os.path.normpath(www_root)):
        return ""  # tentativa de path traversal
    return full_path
