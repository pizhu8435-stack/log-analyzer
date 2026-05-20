from flask import Flask,render_template
from detector import detect_attack

app = Flask(__name__)

logs=[]

with open("access.log","r") as f:
    for line in f:
        result = detect_attack(line)

        if result:
            logs.append({
                "type": result,
                "content":line
            })

@app.route("/")
def index():

    return render_template("index.html",logs=logs)

if __name__=="__main__":
    app.run(debug=True)
