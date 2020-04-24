import re
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def die(message, code=1):
    eprint(message)
    sys.exit(code)

class HTTPHeader:
    first_line_pat = re.compile(r"([A-Z]+) (\S+) (HTTP\/\d+\.\d+)")
    url_pat = re.compile(r"https?:\/\/(\S+?)?(\/(\S+)?)")
    tunn_pat = re.compile(r"(\S+):\d+")

    @classmethod
    def parse(cls, header_str):
        request = {}
        headers = {}

        lines = header_str.split("\r\n")
        for line in lines:
            if not len(line.strip()):
                continue
            match = cls.first_line_pat.match(line)
            if match:
                request["method"] = match[1]
                request["url"] = match[2]
                request["version"] = match[3]

                if request["url"].startswith("http://") or request["url"].startswith("https://"):
                    url_match = cls.url_pat.match(request["url"])
                    request["hostname"] = url_match[1]
                    request["path"] = url_match[2]
                else:
                    tunn_match = cls.tunn_pat.match(request["url"])
                    request["hostname"] = tunn_match[1]
            else:
                [key, value] = line.split(": ")
                if key == "Proxy-Connection":
                    key = "Connection"
                headers[key] = value
        
        # print("[HTTPHeader.parse]", request, headers)
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
