"""Gap sink -- the evidence collector for the DISCLOSED AF_INET-scope limit.

agent/listener.py binds 127.0.0.1:9000 (AF_INET) and is sealed. This sink
listens on the address families leash does NOT enforce, so an attack that walks
through the gap has somewhere to land and be recorded:

  * IPv6 TCP  [::1]:9000
  * AF_UNIX   <runtime>/leash-sink.sock

Anything arriving here arrived because socket_connect only inspects AF_INET
(bpf/leash_connect.bpf.c: `sa_family != AF_INET -> return 0`). Every record is
tagged with its family and appended to sink6.log. Loopback / local only, per
charter invariant 3.

  python3 sink6.py [--dir DIR]      # DIR holds sink6.log + the unix socket
"""
import argparse
import datetime
import os
import socket
import socketserver
import threading

LOGLOCK = threading.Lock()


def log(logpath, family, peer, data):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    rec = f"=== {ts} family={family} peer={peer}\n{data}\n\n"
    with LOGLOCK:
        with open(logpath, "a") as f:
            f.write(rec)


class V6Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(8192).decode("utf-8", "replace")
        log(self.server.logpath, "AF_INET6", self.client_address[:2], data)
        # speak just enough HTTP that a curl to us gets a clean 200
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")


class UnixHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(8192).decode("utf-8", "replace")
        log(self.server.logpath, "AF_UNIX", "unix", data)
        self.request.sendall(b"OK")


class V6Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True


class UnixServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.expanduser("~/leash-demo"))
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()

    logpath = os.path.join(args.dir, "sink6.log")
    sockpath = os.path.join(args.dir, "leash-sink.sock")
    if os.path.exists(sockpath):
        os.unlink(sockpath)

    v6 = V6Server(("::1", args.port), V6Handler)
    v6.logpath = logpath
    ux = UnixServer(sockpath, UnixHandler)
    ux.logpath = logpath

    threading.Thread(target=v6.serve_forever, daemon=True).start()
    threading.Thread(target=ux.serve_forever, daemon=True).start()
    print(f"sink6  tcp6 [::1]:{args.port}   unix {sockpath}")
    print(f"  log : {logpath}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nsink6 down")


if __name__ == "__main__":
    main()
