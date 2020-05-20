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

CACHEABLE_METHODS = ["GET", "HEAD"]

def is_cacheable(method: str, response: dict, headers: dict):
    """
    Returns True if the resource is cacheable; False otherwise.
    """
    # https://developer.mozilla.org/en-US/docs/Glossary/cacheable
    return \
        method in CACHEABLE_METHODS \
        and response["status"]["code"] in [200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501]

def sock_recv(sock, size):
    return sock.recv(size)

    # '''Wrap the call to recv in a try...except'''
    # try:
    #     return sock.recv(size)
    # # except ConnectionAbortedError:
    # except:
    #     return b""  # treat same as connection closed

def sock_close(*socks):
    for sock in socks:
        sock.close()

def forward_responses(dest_sock, client_sock):
    eprint("SPAWNED forward_responses:", dest_sock, client_sock)
    while True:
        try:
            dest_d = sock_recv(dest_sock, 4096)
        except:
            # eprint("DESTINATION SOCKED DIED")
            break
        if dest_d == b"":
            break
        # eprint(f"READ FROM {dest_sock.getpeername()}:", dest_d)
        client_sock.send(dest_d)
        # eprint("FORWARDED TO CLIENT")

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
                request["version"] + " " + status_message + ENDL
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
                request["version"] + " " + status_message + ENDL
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
        print(f"Tunnel: connection established with {dest_ip}:{dest_port}")
        client_sock.send(bytes(request["version"] + " 200 Connection Established", ENC) + TERMB)

    if is_tunnel:
        eprint("TUNNEL MODE")

        # start process to relay data from destination to client
        Process(target=forward_responses, args=(dest_sock, client_sock)).start()

        recvbuf = b""
        while True:
            # print("wait for client")
            recvbuf = sock_recv(client_sock, RECV_SIZE)
            # print("recvbuf:", recvbuf)
            # print("done waiting for client")
            if not len(recvbuf):
                return sock_close(client_sock, dest_sock)
            size = len(recvbuf)
            sent = 0
            while sent < size:
                sent += dest_sock.send(recvbuf[sent:])
        # o tunnel mode, thine simplicity bewilst me unto joy
    else:
        eprint("HTTP MODE")
        is_header = True
        body_left = 0
        wait_for_dest = False  # True -> request complete, wait for response;
                               #         i.e. it is dest's turn

        resource_method = None
        resource_hostname = None
        resource_path = None  # keep track of the URL for cacheing
        cache_file = None
        is_cache_validate = False
        responded_from_cache = False

        while True:
            if not wait_for_dest:
                is_cache_validate = False
                responded_from_cache = False
                if cache_file is not None:
                    eprint(f"Closing (write) cache file '{cache_file.name}'...")
                    cache_file.close()
                    cache_file = None
                # eprint("client's turn")
                if is_header and recvbuf.endswith(TERMB):  # done collecting headers
                    request, headers = HTTPHeader.parse(recvbuf.decode(ENC))
                    eprint(request)

                    resource_hostname = request["hostname"]
                    resource_path = request["path"]
                    resource_method = request["method"]

                    # check if we have the requested resource in cache
                    request_is_conditional = bool(
                        dict_get_insensitive(headers, "If-Modified-Since")
                        or dict_get_insensitive(headers, "ETag")
                        )
                    # leave the request alone if client is already doing conditional
                    if resource_method in CACHEABLE_METHODS and not request_is_conditional:
                        resource_url = "http://" + resource_hostname + resource_path
                        cache_metadata = cache.get_metadata(resource_url)  # None or (<last modified>, <etag>)
                        if cache_metadata is not None and cache_metadata[0] is not None:
                            is_cache_validate = True
                            headers["If-Modified-Since"] = cache_metadata[0]
                            # modifies the client's request into a conditional
                            # based on our cached metadata

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
            else:  # wait_for_dest == True
                # eprint("dest's turn")

                dest_d = sock_recv(dest_sock, 1)
                if not dest_d:
                    return sock_close(client_sock, dest_sock)
                recvbuf += dest_d
                if is_header and recvbuf.endswith(TERMB):  # done collecting headers
                    response, headers = HTTPHeader.parse(recvbuf.decode(ENC), is_response=True)
                    eprint(response)
                    resource_url = "http://" + resource_hostname + resource_path

                    if is_cacheable(resource_method, response, headers):
                        cache.create_entry(resource_url)
                        cache_file = cache.open_file(resource_url, "wb")

                        # insert a custom x-header at the bottom
                        mod_recvbuf = recvbuf[:-2] + b"X-zjguard-Cache: 1\r\n" + recvbuf[-2:]

                        cache_file.write(mod_recvbuf[:-1])  # chop off the last byte ('\n'), otherwise
                                                            # it will be double-written below

                    if is_cache_validate and response["status"]["code"] == 304:  # Not Modified
                        # just send client what we have in cache and go back to client's turn
                        # note that this block is mutually exclusive with the
                        # above block, since 304 is not cacheable
                        with cache.open_file(resource_url, "rb") as f:
                            print(f"RESPONDING FROM CACHE: {f.name}")
                            cbd = f.read(48)  # arbitrary size
                            while cbd:
                                # print("send from cache:", cbd)
                                client_sock.send(cbd)
                                cbd = f.read(48)
                        responded_from_cache = True
                        wait_for_dest = False
                        is_cache_validate = False
                    # else, echo back to client and save to cache as usual...

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
                    if not is_cache_validate and not responded_from_cache:
                        # print("send from dest:", dest_d, "; responded_from_cache =", responded_from_cache)
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
        die("config.json not found. Please create it and enter the configuation settings.")

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
