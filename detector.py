def detect_attack(line):
    line = line.lower() #统一转小写，防止大小写绕过
    if "union select" in line:
        return "SQL Injection"
    elif "<script>" in line:
        return "xss"
    elif "../" in line:
        return "File Inclusion"
    else:
        return None