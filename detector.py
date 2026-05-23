def detect_attack(url):
    url = url.lower() #统一转小写，防止大小写绕过
    if "union select" in url:
        return "SQL Injection"
    elif "<script>" in url:
        return "xss"
    elif "../" in url:
        return "File Inclusion"
    else:
        return None