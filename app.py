from flask import Flask, render_template

from parser import parse_log
from detector import detect_attack, detect_scanner


app = Flask(__name__)

logs = []

ip_count= {}

with open("access.log", "r") as f:

    for line in f:

        parsed = parse_log(line)

        if parsed:

            attack = detect_attack(parsed["url"])

            if attack:

                ip = parsed["ip"]
                scanner = detect_scanner(parsed["user_agent"])

                if ip in ip_count:
                    ip_count[ip]+=1
                else:
                    ip_count[ip]=1

                parsed["attack_type"] = attack["type"]
                parsed["risk_level"] = attack["level"]
                parsed["scanner"] = scanner

                logs.append(parsed)

@app.route("/")
def index():

    return render_template("index.html", logs=logs,ip_count=ip_count)

if __name__ == "__main__":
    app.run(debug=True)
