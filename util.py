import re
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def die(message, code=1):
    eprint(message)
    sys.exit(code)

class HTTPHeader:
    req_line_pat = re.compile(r"([A-Z]+) (\S+) (HTTP\/\d+\.\d+)")
    res_line_pat = re.compile(r"(HTTP/\d+\.\d+) ((\d{3}) (.+))")  # e.g. HTTP/1.1 404 Not Found
    url_pat = re.compile(r"https?:\/\/(\S+?)?(\/(\S+)?)")
    tunn_pat = re.compile(r"(\S+):\d+")

    @classmethod
    def parse(cls, header_str, is_response=False):
        request = {}
        response = {}
        headers = {}

        lines = header_str.split("\r\n")
        for line in lines:
            if not len(line.strip()):
                continue
            match_req = cls.req_line_pat.match(line)
            match_res = cls.res_line_pat.match(line)
            if match_req:
                request["method"] = match_req[1]
                request["url"] = match_req[2]
                request["version"] = match_req[3]

                if request["url"].startswith("http://") or request["url"].startswith("https://"):
                    url_match = cls.url_pat.match(request["url"])
                    request["hostname"] = url_match[1]
                    request["path"] = url_match[2]
                else:
                    tunn_match = cls.tunn_pat.match(request["url"])
                    request["hostname"] = tunn_match[1]
            elif match_res:
                response["version"] = match_res[1]
                response["status"] = {
                    "code": int(match_res[3]),  # 404
                    "phrase": match_res[4],     # "Not Found"
                    "message": match_res[2],    # "404 Not Found"
                }
            else:
                [key, value] = line.split(": ")
                if key == "Proxy-Connection":
                    key = "Connection"
                headers[key] = value

        # print("[HTTPHeader.parse]", request, headers)
        if is_response:
            return response, headers
        else:
            return request, headers

    @classmethod
    def generate(cls, request, headers):
        lines = []
        if request["method"] == "CONNECT":
            return
            # lines.append("%s %s:443 %s".format(request["method"], request["hostname"], request["version"]))
        else:
            lines.append("{} {} {}".format(request["method"], request["path"], request["version"]))
        if not "Host" in headers:
            lines.append("Host: {}".format(request["hostname"]))
        for key in headers:
            lines.append(f"{key}: {headers[key]}")
        return "\r\n".join(lines)
