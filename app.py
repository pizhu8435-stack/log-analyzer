from flask import Flask, render_template

from parser import parse_log
from detector import detect_attack

app = Flask(__name__)

logs = []

with open("access.log", "r") as f:

    for line in f:

        parsed = parse_log(line)

        if parsed:

            attack = detect_attack(parsed["url"])

            if attack:

                parsed["attack"] = attack

                logs.append(parsed)

@app.route("/")
def index():

    return render_template("index.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
