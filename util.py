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
        resource = {}
        headers = {}

        lines = header_str.split("\r\n")
        for line in lines:
            match = cls.first_line_pat.match(line)
            if match:
                resource["method"] = match[1]
                resource["url"] = match[2]
                resource["version"] = match[3]

                if resource["url"].startswith("http://") or resource["url"].startswith("https://"):
                    url_match = cls.url_pat.match(resource["url"])
                    resource["hostname"] = url_match[1]
                    resource["path"] = url_match[2]
                else:
                    tunn_match = cls.tunn_pat.match(resource["url"])
                    resource["hostname"] = tunn_match[1]
            else:
                [key, value] = line.split(": ")
                headers[key] = value
        
        return resource, headers
    
    @classmethod
    def generate(cls, resource, headers):
        lines = []
        if resource["method"] == "CONNECT":
            return
            # lines.append("%s %s:443 %s".format(resource["method"], resource["hostname"], resource["version"]))
        else:
            lines.append("{} {} {}".format(resource["method"], resource["path"], resource["version"]))
        if not "Host" in headers:
            lines.append("Host: {}".format(resource["hostname"]))
        for key in headers:
            lines.append(f"{key}: {headers[key]}")
        return "\r\n".join(lines)
