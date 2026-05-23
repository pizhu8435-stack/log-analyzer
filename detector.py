def detect_attack(url):
    url = url.lower() #统一转小写，防止大小写绕过
    if "union select" in url:
        return {
            "type": "SQL Injection",
            "level": "High"
        }
    elif "<script>" in url:
        return{
            "type": "xss",
            "level": "Medium"
        }
    elif "../" in url:
        return {
            "type": "File Inclusion",
            "level": "High"
        }
    else:
        return None

def detect_scanner(user_agent):

    user_agent = user_agent.lower()

    if "sqlmap" in user_agent:
        return "SQLMap"

    elif "curl" in user_agent:
        return "Curl"

    elif "python-requests" in user_agent:
        return "Python Requests"

    elif "nikto" in user_agent:
        return "Nikto"

    return None