#!/usr/bin/env python3
"""Bootstrap one disposable account on a localhost-only independent Ergo IRCd.

No production secrets. The password below is intentionally public synthetic
test data, valid only for the per-job temporary IRC server. Never run this
script against an operational server or store real credentials in source.
"""
import os
import socket
import ssl
import time

NICK = "rustisynacct"
PASSWORD = "synthetic-ci-credential-2026"
MAX_LINE = 4096
MAX_BUFFER = 16384


class BoundedTlsLines:
    """Incremental, bounded TLS reader; safe after read timeouts."""

    def __init__(self, tls):
        self.tls = tls
        self.buffer = bytearray()

    def read(self, deadline):
        while time.monotonic() < deadline:
            marker = self.buffer.find(b"\n")
            if marker >= 0:
                if marker + 1 > MAX_LINE:
                    raise RuntimeError("IRC bootstrap line limit exceeded")
                line = bytes(self.buffer[:marker + 1])
                del self.buffer[:marker + 1]
                if not line.endswith(b"\r\n"):
                    raise RuntimeError("Malformed IRC bootstrap terminator")
                if line.startswith(b"PING "):
                    challenge = line[5:-2]
                    if len(challenge) > 256 or b"\r" in challenge or b"\n" in challenge:
                        raise RuntimeError("Invalid server PING")
                    self.tls.sendall(b"PONG " + challenge + b"\r\n")
                    continue
                return line

            self.tls.settimeout(max(0.05, min(1.0, deadline - time.monotonic())))
            try:
                received = self.tls.recv(2048)
            except (TimeoutError, socket.timeout):
                continue
            if not received:
                raise RuntimeError("IRC bootstrap TLS connection closed")
            self.buffer.extend(received)
            if len(self.buffer) > MAX_BUFFER:
                raise RuntimeError("IRC bootstrap buffer limit exceeded")
        raise TimeoutError("No qualifying IRC bootstrap response before deadline")


def nickserv_notice(line):
    """Returns a control-scrubbed notice body only for the NickServ sender."""
    fields = line.split(b" ", 3)
    if len(fields) != 4:
        return None
    sender = fields[0].lstrip(b":").split(b"!")[0].upper()
    if sender != b"NICKSERV" or fields[1].upper() != b"NOTICE":
        return None
    body = fields[3].lstrip(b":").strip().upper()
    # Do not log remote content, account names or passwords.
    return body


def main():
    endpoint = os.environ.get("RUSTI_ERGO_ADDR", "")
    pem = os.environ.get("RUSTI_ERGO_CA_PEM", "")
    if endpoint != "127.0.0.1:16697" or not pem:
        raise RuntimeError("Only the exact localhost test endpoint is supported")
    context = ssl.create_default_context(cafile=pem)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", 16697), timeout=4) as tcp:
        with context.wrap_socket(tcp, server_hostname="localhost") as tls:
            reader = BoundedTlsLines(tls)
            tls.sendall(
                f"NICK {NICK}\r\nUSER {NICK} 0 * :synthetic-irc-account-fixture\r\n".encode()
            )
            deadline = time.monotonic() + 12
            while True:
                line = reader.read(deadline)
                if b" 001 " in line:
                    break
                if b" 433 " in line or b" ERROR " in line:
                    raise RuntimeError("Bootstrap IRC nickname refused")

            tls.sendall(f"PRIVMSG NickServ :REGISTER {PASSWORD}\r\n".encode())
            deadline = time.monotonic() + 12
            notices_seen = 0
            while True:
                line = reader.read(deadline)
                body = nickserv_notice(line)
                if body is None:
                    continue
                notices_seen += 1
                if any(bad in body for bad in (
                    b"ALREADY REGISTERED", b"ERROR", b"UNABLE", b"FAILED",
                    b"INVALID", b"DISABLED", b"REJECTED", b"NOT ALLOWED",
                    b"PENDING VERIFICATION", b"REQUIRES",
                )):
                    raise RuntimeError("Independent IRCd refused synthetic account enrollment")
                if b"REGISTERED" in body or b"SUCCESSFUL" in body:
                    break
                if b"CREATED" in body and b"PENDING" not in body:
                    break
            tls.sendall(b"QUIT :synthetic-bootstrap-finished\r\n")
    print("Ephemeral NickServ registration completed through verified localhost TLS")


if __name__ == "__main__":
    main()
