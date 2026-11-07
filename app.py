
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from flask_bcrypt import Bcrypt
import sqlite3
import os
import re
import secrets
import hmac

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-before-deployment"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800

bcrypt = Bcrypt(app)

DATABASE = "users.db"


# Database connection
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Create database
def create_table():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# CSRF protection
def generate_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf


def check_csrf():
    submitted = request.form.get("csrf_token", "")
    saved = session.get("csrf_token", "")

    return bool(saved) and hmac.compare_digest(submitted, saved)


# Home
@app.route("/")
def home():
    return redirect(url_for("register"))


# Registration page
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        if not check_csrf():
            return "Invalid request. Please refresh the page.", 400

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            flash("Username must be 3-20 letters, numbers or underscores.")
            return redirect(url_for("register"))

        if not re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            email
        ):
            flash("Please enter a valid email.")
            return redirect(url_for("register"))

        if len(password) < 8 or len(password.encode("utf-8")) > 72:
            flash("Password must be 8 or more characters and at most 72 bytes.")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        conn = get_db()

        try:
            conn.execute("""
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
            """, (username, email, hashed_password))

            conn.commit()
            flash("Registration successful! Please login.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username or email already exists.")
            return redirect(url_for("register"))

        finally:
            conn.close()

    return render_template("register.html")


# Login page
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if not check_csrf():
            return "Invalid request. Please refresh the page.", 400

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and bcrypt.check_password_hash(
            user["password"], password
        ):

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True

            flash("Login successful!")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


# Dashboard
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# Logout
@app.route("/logout", methods=["POST"])
def logout():

    if not check_csrf():
        return "Invalid request. Please refresh the page.", 400

    session.clear()

    flash("You have logged out successfully.")

    return redirect(url_for("login"))


if __name__ == "__main__":

    create_table()

    app.run(debug=True)
