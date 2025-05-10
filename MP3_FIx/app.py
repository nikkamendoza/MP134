
import secrets
import sqlite3

from flask import Flask, request, render_template, redirect
from flask_wtf.csrf import CSRFProtect, CSRFError

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)  # Generate a secure secret key
csrf = CSRFProtect(app)
con = sqlite3.connect("app.db", check_same_thread=False)
con.row_factory = sqlite3.Row  # Enable row factory for named columns

# Add this function to handle CSRF errors
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    cur = con.cursor()
    if request.method == "GET":
        if request.cookies.get("session_token"):
            # Use parameterized query
            res = cur.execute(
                "SELECT username FROM users INNER JOIN sessions ON users.id = sessions.user WHERE sessions.token = ?",
                (request.cookies.get("session_token"),)
            )
            user = res.fetchone()
            if user:
                return redirect("/home")

        return render_template("login.html")
    else:
        # Use parameterized query
        res = cur.execute(
            "SELECT id from users WHERE username = ? AND password = ?",
            (request.form["username"], request.form["password"])
        )
        user = res.fetchone()
        if user:
            token = secrets.token_hex()
            # Use parameterized query
            cur.execute(
                "INSERT INTO sessions (user, token) VALUES (?, ?)",
                (user[0], token)
            )
            con.commit()
            response = redirect("/home")
            # Set secure cookie options
            response.set_cookie(
                "session_token", 
                token,
                httponly=True,  # Prevents JavaScript access
                samesite="Lax"  # Prevents CSRF
            )
            return response
        else:
            return render_template("login.html", error="Invalid username and/or password!")

@app.route("/")
@app.route("/home")
def home():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        # Use parameterized query
        res = cur.execute(
            "SELECT users.id, username FROM users INNER JOIN sessions ON users.id = sessions.user WHERE sessions.token = ?",
            (request.cookies.get("session_token"),)
        )
        user = res.fetchone()
        if user:
            # Use parameterized query
            res = cur.execute(
                "SELECT message FROM posts WHERE user = ?",
                (user[0],)
            )
            posts = res.fetchall()
            return render_template("home.html", username=user[1], posts=posts)

    return redirect("/login")


@app.route("/posts", methods=["POST"])
def posts():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        # Use parameterized query
        res = cur.execute(
            "SELECT users.id, username FROM users INNER JOIN sessions ON users.id = sessions.user WHERE sessions.token = ?",
            (request.cookies.get("session_token"),)
        )
        user = res.fetchone()
        if user:
            # Use parameterized query
            cur.execute(
                "INSERT INTO posts (message, user) VALUES (?, ?)",
                (request.form["message"], user[0])
            )
            con.commit()
            return redirect("/home")

    return redirect("/login")


@app.route("/logout", methods=["GET"])
def logout():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        # Use parameterized query
        res = cur.execute(
            "SELECT users.id, username FROM users INNER JOIN sessions ON users.id = sessions.user WHERE sessions.token = ?",
            (request.cookies.get("session_token"),)
        )
        user = res.fetchone()
        if user:
            # Use parameterized query
            cur.execute(
                "DELETE FROM sessions WHERE user = ?",
                (user[0],)
            )
            con.commit()

    response = redirect("/login")
    # Clear the cookie with the same settings
    response.set_cookie("session_token", "", expires=0, httponly=True, samesite="Lax")
    return response

if __name__ == "__main__":
    app.run(debug=True)