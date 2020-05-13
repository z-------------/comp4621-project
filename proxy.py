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

RECV_SIZE = 4096

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

def get_status_message(code: int):
    return str(code) + " " + HTTPStatus(code).phrase

def is_cacheable(method: str, response: dict, headers: dict):
    """
    Returns True if the resource is cacheable; False otherwise.
    """
    # https://developer.mozilla.org/en-US/docs/Glossary/cacheable
    return \
        method in ["GET", "HEAD"] \
        and response["status"]["code"] in [200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501]

def sock_recv(sock, size):
    '''Wrap the call to recv in a try...except'''
    try:
        return sock.recv(size)
    # except ConnectionAbortedError:
    except:
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

    # access control
    if request["hostname"] in cfg["access_control"]["domains"]:
        eprint("ACCESS CONTROL: Blocked attempt to access {}".format(request["hostname"]))
        status_message = get_status_message(cfg["access_control"]["status"])
        client_sock.send(
            bytes(
                request["version"] + f" {status_message}" + ENDL
                + "Connection: close" + ENDL
                + f"Content-Length: {len(status_message)}" + ENDL
                + ENDL
                + status_message + ENDL,
                ENC
                )
            )
        return sock_close(client_sock)

    # resolve address
    try:
        dest_ip = gethostbyname(request["hostname"])
    except: # name resolution failed
        status_message = get_status_message(404)
        client_sock.send(
            bytes(
                request["version"] + f" {status_message}" + ENDL
                + "Connection: close" + ENDL
                + f"Content-Length: {len(status_message)}" + ENDL
                + ENDL
                + status_message + ENDL,
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
    # Process(target=forward_responses, args=(dest_sock, request["hostname"], client_sock, is_tunnel)).start()

    if is_tunnel:
        # eprint("TUNNEL MODE")
        recvbuf = b""
        while True:
            recvbuf = sock_recv(client_sock, RECV_SIZE)
            if not len(recvbuf):
                return sock_close(client_sock, dest_sock)
            size = len(recvbuf)
            sent = 0
            while sent < size:
                sent += dest_sock.send(recvbuf[sent:])
        # O tunnel mode, thine simplicity bewilst me unto joy
    else:
        # eprint("HTTP MODE")
        is_header = True
        body_left = 0
        wait_for_dest = False  # True -> request complete, wait for response;
                               #         i.e. it is dest's turn

        resource_method = None
        resource_hostname = None
        resource_path = None  # keep track of the URL for cacheing
        cache_file = None

        while True:
            if not wait_for_dest:
                if cache_file is not None:
                    eprint(f"Closing cache file '{cache_file.name}'...")
                    cache_file.close()
                    cache_file = None
                # eprint("client's turn")
                if is_header and recvbuf.endswith(TERMB):  # done collecting headers
                    request, headers = HTTPHeader.parse(recvbuf.decode(ENC))
                    eprint(request)

                    resource_hostname = request["hostname"]
                    resource_path = request["path"]
                    resource_method = request["method"]

                    header_b = bytes(HTTPHeader.generate(request, headers), ENC) + TERMB
                    dest_sock.send(header_b)  # forward to dest
                    body_left = int(headers.get("Content-Length", 0))
                    if body_left > 0:
                        is_header = False
                    else:
                        wait_for_dest = True
                    recvbuf = b""
                elif not is_header:  # receiving body
                    dest_sock.send(recvbuf)  # forward to dest
                    body_left -= 1
                    recvbuf = b""
                    if body_left == 0:
                        is_header = True
                        wait_for_dest = True
                if not wait_for_dest:
                    recvbuf += sock_recv(client_sock, 1)
                    if not recvbuf:
                        return sock_close(client_sock, dest_sock)
                # TODO conditionally fulfil requests using cache
            else:  # wait_for_dest == True
                # eprint("dest's turn")
                dest_d = sock_recv(dest_sock, 1)
                if not dest_d:
                    return sock_close(client_sock, dest_sock)
                recvbuf += dest_d
                if is_header and recvbuf.endswith(TERMB):  # done collecting headers
                    response, headers = HTTPHeader.parse(recvbuf.decode(ENC), is_response=True)
                    eprint(response)
                    if is_cacheable(resource_method, response, headers):
                        resource_url = "http://" + resource_hostname + resource_path
                        cache.create_entry(resource_url)
                        cache_file = cache.open_file(resource_url, "wb")
                        cache_file.write(recvbuf)
                    body_left = int(headers.get("Content-Length", 0))
                    if body_left > 0:
                        is_header = False
                    else:
                        wait_for_dest = False
                    recvbuf = b""
                elif not is_header:  # receiving body
                    body_left -= 1
                    recvbuf = b""
                    if body_left == 0:
                        is_header = True
                        wait_for_dest = False
                try:
                    client_sock.send(dest_d)  # forward to client
                    if cache_file is not None:
                        cache_file.write(dest_d)  # write to cache file
                except:
                    return sock_close(client_sock, dest_sock)


if __name__ == "__main__":
    # load config
    try:
        with open("config.json", "r") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        eprint("config.json not found. Please create it and enter the configuation settings.")
        sys.exit(1)

    # create cache directory
    cache.createdir()

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
