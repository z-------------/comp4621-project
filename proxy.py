#!/usr/bin/env python3

from multiprocessing import Process
from socket import *

from util import *

PORT = 8081

PORT_HTTP = 80
PORT_HTTPS = 443

ENC = "utf-8"

ENDL = "\r\n"
TERM = "\r\n\r\n"
TERMB = bytes(TERM, ENC)

def process_request(client_sock, client_addr):
    eprint(client_sock, client_addr)
    
    dest_connected = False

    buffer = b""

    while True:
        if len(buffer) == 0:
            buffer += client_sock.recv(4096)
        if buffer == b"": # recv returns empty string if connection closed
            break
            
        while (buffer.find(TERMB) == -1):
            buffer += client_sock.recv(4096)

        data_split = buffer.split(TERMB, 1)
        # eprint(data_split)

        buffer = b"" # clear buffer for next round

        # header
        header_data = data_split[0]
        rest_data = data_split[1]
        header_str = header_data.decode(ENC)
        resource, headers = HTTPHeader.parse(header_str)
        eprint(resource, headers)

        # body
        body_length = int(headers.get("Content-Length", 0))
        body_left = body_length - len(rest_data)
        if body_left < 0: # `rest_data` contains part of the next request
            eprint("ROUTE ONE")
            body_data = rest_data[:body_left]
            buffer = rest_data[body_left:]
        elif body_left > 0:
            eprint("ROUTE TWO")
            body_data = b""
            while (body_left > 0):
                d = client_sock.recv(4096)
                body_data += d
                body_left -= len(d)
            if body_left < 0:
                eprint("ROUTE THREE")
                body_data = body_data[:body_left]
                buffer = body_data[body_left:]
        else:
            body_data = rest_data
        
        eprint(body_data)

        eprint(bytes(HTTPHeader.generate(resource, headers), ENC))

        dest_port = PORT_HTTPS if resource["method"] == "CONNECT" else PORT_HTTP
        dest_ip = gethostbyname(resource["hostname"])
        dest_sock = socket(AF_INET, SOCK_STREAM)
        dest_sock.connect((dest_ip, dest_port))
        dest_sock.send(bytes(HTTPHeader.generate(resource, headers), ENC) + TERMB)
        dest_sock.send(body_data)

        while True:
            dest_d = dest_sock.recv(4096)
            if dest_d == b"":
                break
            client_sock.send(dest_d)

        eprint("LOOP BOTTOM")

    client_sock.close()

if __name__ == "__main__":
    serv_sock = socket(AF_INET, SOCK_STREAM)
    serv_sock.bind(("0.0.0.0", PORT))
    serv_sock.listen()

    eprint(f"Listening on :{PORT}")

    while True:
        client_sock, client_addr = serv_sock.accept()
        p = Process(target=process_request, args=(client_sock, client_addr))
        p.start()
