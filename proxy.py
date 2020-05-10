#!/usr/bin/env python3

import json

from multiprocessing import Process
from socket import *
from http import HTTPStatus

from util import *
import cache

PORT_HTTP = 80
PORT_HTTPS = 443

ENC = "utf-8"

ENDL = "\r\n"
ENDLB = bytes(ENDL, ENC)
TERM = "\r\n\r\n"
TERMB = bytes(TERM, ENC)

def get_parts(data: bytes):
    if TERMB not in data:
        return None
    return data.split(TERMB)

def get_headers(data: bytes):
    parts = get_parts(data)
    if parts is None:
        return None
    return HTTPHeader.parse(parts[0])

def get_body(data: bytes):
    parts = get_parts(data)
    if parts is None:
        return None
    return parts[1]

def sock_recv(sock, size):
    '''Wrap the call to recv in a try...except'''
    try:
        return sock.recv(size)
    except ConnectionAbortedError:
        return b""  # treat same as connection closed

def sock_close(*socks):
    for sock in socks:
        sock.close()

def process_request(client_sock, cfg):
    recvbuf = b""

    # read one byte at a time until we have the whole header
    while not recvbuf.endswith(TERMB):
        recvbuf += sock_recv(client_sock, 1)

    # connect to destination

    request, headers = HTTPHeader.parse(recvbuf.decode(ENC))
    is_tunnel = request["method"] == "CONNECT"

    # refuse if hostname blocked by access control
    if request["hostname"] in cfg["access_control"]["domains"]:
        eprint("ACCESS CONTROL: Blocked attempt to access {}".format(request["hostname"]))
        status_code = cfg["access_control"]["status"]
        status_message = HTTPStatus(status_code).phrase
        client_sock.send(
            bytes(
                request["version"] + f" {status_code} {status_message}" + ENDL
                + "Connection: close" + ENDL
                + "Content-Length: 0" + ENDL
                + ENDL,
                ENC
                )
            )
        return sock_close(client_sock)

    # resolve address
    try:
        dest_ip = gethostbyname(request["hostname"])
    except: # name resolution failed
        client_sock.send(
            bytes(
                request["version"] + " 404 Not Found" + ENDL
                + "Connection: close" + ENDL
                + "Content-Length: 0" + ENDL
                + ENDL,
                ENC
                )
            )
        return sock_close(client_sock)

    # connect
    dest_port = PORT_HTTPS if is_tunnel else PORT_HTTP
    dest_sock = socket(AF_INET, SOCK_STREAM)
    dest_sock.connect((dest_ip, dest_port))
    if is_tunnel:
        client_sock.send(bytes(request["version"] + " 200 Connection Established", ENC) + TERMB)

    # start process to relay data from destination to client
    Process(target=forward_responses, args=(dest_sock, client_sock)).start()

    if is_tunnel:
        # eprint("TUNNEL MODE")
        recvbuf = b""
        while True:
            recvbuf = sock_recv(client_sock, 4096)
            if not len(recvbuf):
                return sock_close(client_sock, dest_sock)
            size = len(recvbuf)
            sent = 0
            while sent < size:
                sent += dest_sock.send(recvbuf[sent:])
    else:
        # eprint("HTTP MODE")
        is_header = True
        body_left = 0
        while True:
            if is_header and recvbuf.endswith(TERMB):  # done collecting headers
                is_header = False
                request, headers = HTTPHeader.parse(recvbuf.decode(ENC))
                header_b = bytes(HTTPHeader.generate(request, headers), ENC) + TERMB
                dest_sock.send(header_b)
                body_left = int(headers.get("Content-Length", 0))
                recvbuf = b""
            elif not is_header:  # receiving body
                dest_sock.send(recvbuf)
                body_left -= 1
                recvbuf = b""
                if body_left == 0:
                    is_header = True
            recvbuf += sock_recv(client_sock, 1)
            if not len(recvbuf):
                return sock_close(client_sock, dest_sock)

def forward_responses(dest_sock, client_sock):
    # eprint("SPAWNED forward_responses:", dest_sock, client_sock)
    while True:
        try:
            dest_d = sock_recv(dest_sock, 4096)
        except:
            eprint("DESTINATION SOCKED DIED")
            break
        if dest_d == b"":
            break
        # eprint(f"READ FROM {dest_sock.getpeername()}:", dest_d)
        client_sock.send(dest_d)
        # eprint("FORWARDED TO CLIENT")

if __name__ == "__main__":
    # load config
    try:
        with open("config.json", "r") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        eprint("config.json not found. Please create it and enter the configuation settings.")
        sys.exit(1)

    # set up server
    serv_addr, serv_port = cfg["server"]["address"], cfg["server"]["port"]
    serv_sock = socket(AF_INET, SOCK_STREAM)
    serv_sock.bind((serv_addr, serv_port))
    serv_sock.listen()

    eprint(f"Listening at {serv_addr}:{serv_port}")

    # handle requests
    while True:
        client_sock, client_addr = serv_sock.accept()
        p = Process(target=process_request, args=(client_sock, cfg))
        p.start()
