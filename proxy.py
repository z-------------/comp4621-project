#!/usr/bin/env python3

from multiprocessing import Process
from socket import *

from util import *

PORT = 8081

PORT_HTTP = 80
PORT_HTTPS = 443

ENC = "utf-8"

ENDL = "\r\n"
ENDLB = bytes(ENDL, ENC)
TERM = "\r\n\r\n"
TERMB = bytes(TERM, ENC)

def process_request(client_sock):
    eprint("\nNEW INCOMING CONNECTION:", client_sock)
    
    dest_sock = None
    dest_connected = False
    tunnel = False

    buffer = b""

    while True:
        eprint("LOOP TOP")

        if len(buffer) == 0:
            eprint("WAITING FOR DATA FROM CLIENT")
            try:
                buffer += client_sock.recv(4096)
            except:
                eprint("FAILED: client_sock.recv")
                break
        if not len(buffer): # recv returns empty string if connection closed
            break

        eprint("RECEIVED DATA FROM CLIENT")
        eprint("CURRENT BUFFER:", buffer)
            
        if not tunnel: # http
            while (buffer.find(TERMB) == -1): # wait for whole http header
                buffer += client_sock.recv(4096)

            data_split = buffer.split(TERMB, 1)
            # eprint(data_split)

            buffer = b"" # clear buffer for next round

            # header
            header_data = data_split[0]
            rest_data = data_split[1]
            header_str = header_data.decode(ENC)
            resource, headers = HTTPHeader.parse(header_str)
            eprint("RESOURCE:", resource)
            eprint("HEADERS:", headers)

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
        
            eprint("BODY DATA:", body_data)

            # eprint("CONVERTED HEADER:", bytes(HTTPHeader.generate(resource, headers), ENC))

            is_connect = resource["method"] == "CONNECT"

            if not dest_connected:
                dest_port = PORT_HTTPS if is_connect else PORT_HTTP
                try:
                    dest_ip = gethostbyname(resource["hostname"])
                except: # name resolution failed
                    response = bytes(
                        resource["version"] + " 404 Not Found" + ENDL
                        + "Connection: close" + ENDL
                        + "Content-Length: 0" + ENDL
                        + ENDL,
                        ENC
                        )
                    eprint("NAME RES FAILED; SENDING 404")
                    client_sock.send(response)
                    break
                dest_sock = socket(AF_INET, SOCK_STREAM)
                dest_sock.connect((dest_ip, dest_port))
                dest_connected = True
                if is_connect:
                    tunn_response = bytes(resource["version"] + " 200 Connection Established", ENC) + TERMB
                    eprint("SENDING 200 CONNECTION ESTABLISHED:", tunn_response)
                    client_sock.send(tunn_response)
                    tunnel = True
                p = Process(target=forward_responses, args=(dest_sock, client_sock))
                p.start()
            if not is_connect:
                dest_sock.send(bytes(HTTPHeader.generate(resource, headers), ENC) + TERMB)
            if len(body_data):
                dest_sock.send(body_data)
        else: # https through tunnel
            try:
                dest_sock.send(buffer)
                buffer = b"" # clear buffer for next round
            except:
                eprint("FAILED: dest_sock.send")
                break

        eprint("LOOP BOTTOM")

    eprint("CLOSING CLIENT CONNECTION: ", client_sock)
    client_sock.close()
    if dest_sock.fileno() != -1:
        dest_sock.close()
    eprint("FILENO OF CLOSED CONNECTION:", client_sock.fileno())

def forward_responses(dest_sock, client_sock):
    eprint("SPAWNED forward_responses:", dest_sock, client_sock)
    while True:
        try:
            dest_d = dest_sock.recv(4096)
        except:
            eprint("FAILED: dest_sock.recv")
            break
        if dest_d == b"":
            break
        eprint(f"READ FROM {dest_sock.getpeername()}:", dest_d)
        client_sock.send(dest_d)
        eprint("FORWARDED TO CLIENT")

if __name__ == "__main__":
    serv_sock = socket(AF_INET, SOCK_STREAM)
    serv_sock.bind(("0.0.0.0", PORT))
    serv_sock.listen()

    eprint(f"Listening on :{PORT}")

    while True:
        client_sock, client_addr = serv_sock.accept()
        p = Process(target=process_request, args=(client_sock, ))
        p.start()
