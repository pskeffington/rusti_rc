#!/usr/bin/env python3
"""Bootstrap exactly one disposable Ergo account inside an isolated TLS CI lab.

No production secret support. The password below is a publicly known synthetic
test fixture used ONLY on a localhost-bound, per-job ephemeral IRC server.
Never copy this script into an operational deployment or run it against a
public IRC service.
"""
import os
import socket
import ssl
import time

NICK = "rustisynacct"
PASSWORD = "synthetic-ci-credential-2026"
MAX_LINE = 4096


def expect_line(stream, secure_sock, deadline):
    while time.monotonic() < deadline:
        secure_sock.settimeout(max(0.1, min(3.0, deadline - time.monotonic())))
        try:
            line = stream.readline(MAX_LINE + 1)
        except (TimeoutError, socket.timeout):
            continue
        if not line or len(line) > MAX_LINE:
            raise RuntimeError("IRC server closed or exceeded bootstrap line limit")
        if not line.endswith(b"\r\n"):
            raise RuntimeError("Unterminated IRC bootstrap line")
        if line.startswith(b"PING "):
            token = line[5:].strip()
            if b"\r" in token or b"\n" in token or len(token) > 256:
                raise RuntimeError("Invalid server challenge")
            secure_sock.sendall(b"PONG " + token + b"\r\n")
            continue
        return line
    raise TimeoutError("Timed out waiting for IRC registration")


def main():
    endpoint = os.environ.get("RUSTI_ERGO_ADDR", "")
    pem = os.environ.get("RUSTI_ERGO_CA_PEM", "")
    if endpoint != "127.0.0.1:16697" or not pem:
        raise RuntimeError("Only the configured localhost synthetic Ergo lab is supported")
    context = ssl.create_default_context(cafile=pem)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", 16697), timeout=4) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as tls:
            tls.settimeout(3)
            stream = tls.makefile("rb")
            tls.sendall(
                f"NICK {NICK}\r\nUSER {NICK} 0 * :synthetic-irc-account-fixture\r\n".encode()
            )
            deadline = time.monotonic() + 12
            while True:
                line = expect_line(stream, tls, deadline)
                if b" 001 " in line:
                    break
                if b" 433 " in line or b" ERROR " in line:
                    raise RuntimeError("Synthetic IRC account nickname rejected")

            # Password is synthetic and neither an OS keychain secret nor a
            # deployment credential. Do not print raw inbound/outbound lines.
            tls.sendall(f"PRIVMSG NickServ :REGISTER {PASSWORD}\r\n".encode())
            deadline = time.monotonic() + 12
            while True:
                line = expect_line(stream, tls, deadline)
                upper = line.upper()
                if b" NICKSERV " not in upper and b"NICKSERV!" not in upper:
                    continue
                if b"NOTICE" not in upper and b"PRIVMSG" not in upper:
                    continue
                if b"REGISTER" in upper and (b"SUCCESS" in upper or b"REGISTERED" in upper):
                    break
                if any(bad in upper for bad in (
                    b"ALREADY REGISTERED", b"ERROR", b"UNABLE",
                    b"FAILED", b"INVALID", b"DISABLED", b"REJECTED"
                )):
                    raise RuntimeError("Independent IRCd rejected synthetic account registration")

            tls.sendall(b"QUIT :synthetic-bootstrap-finished\r\n")
    print("Ephemeral IRC account registration confirmed over verified localhost TLS")


if __name__ == "__main__":
    main()
