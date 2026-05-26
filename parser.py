import re
from urllib.parse import unquote

def parse_log(line):
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?"(GET|POST) (.*?) HTTP.*? (\d+).*?"(.*?)"$'

    match = re.search(pattern,line)

    if match:
        return{
            "ip":match.group(1),
            "method":match.group(2),
            "url":unquote(match.group(3)),
            "status":match.group(4),
            "user_agent":match.group(5)
        }
    return None
