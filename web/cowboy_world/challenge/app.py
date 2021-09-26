from flask import Flask, render_template, request
import sqlite3

app = Flask(
    __name__,
    template_folder="templates", static_folder="static", static_url_path=''
)

def db_connection():
    conn = None
    try:
        conn = sqlite3.connect("users.sqlite")
    except sqlite3.error as e:
        print(e)
    return e

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        uname = request.form['username']
        pword = request.form['password']
        conn = sqlite3.connect('users.sqlite')
        c = conn.cursor()
        statement = f"SELECT * from users WHERE username=(?) AND password='{pword}';"
        if uname != "sadcowboy":
            return "Incorrect username or password"
        else:
            c.execute(statement,(uname,))
            if not c.fetchone():
                return "Incorrect password"
            else:
                return render_template("/you_did_the_thing.html")
    else: 
        return render_template("index.html")   

@app.route("/wow")
def wow():
    return "wow"

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
