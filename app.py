from flask import Flask, render_template

from parser import parse_log
from detector import detect_attack, detect_scanner


app = Flask(__name__)

logs = []

ip_count= {}

high_risk_count = 0

scanner_count = 0

with open("access.log", "r") as f:

    for line in f:

        parsed = parse_log(line)

        if parsed:

            attack = detect_attack(parsed["url"])

            if attack:

                ip = parsed["ip"]
                scanner = detect_scanner(parsed["user_agent"])

                if scanner:
                    scanner_count += 1
                if ip in ip_count:
                    ip_count[ip]+=1
                else:
                    ip_count[ip]=1

                parsed["attack_type"] = attack["type"]
                parsed["risk_level"] = attack["level"]
                if attack["level"] == "High":
                    high_risk_count += 1
                parsed["scanner"] = scanner

                logs.append(parsed)

@app.route("/")
def index():

    return render_template("index.html", 
        logs=logs, 
        ip_count=ip_count, 
        total_attacks = len(logs),
        high_risk_count = high_risk_count, 
        scanner_count = scanner_count, 
        attack_ip_count = len(ip_count)
    )

if __name__ == "__main__":
    app.run(debug=True)
