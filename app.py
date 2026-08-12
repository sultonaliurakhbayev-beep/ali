from flask import Flask, render_template, request, redirect, url_for, session, flash
from security_ai import SecurityAI
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please")
security_ai = SecurityAI()

ADMIN_USER = {"username": "admin", "password": "Admin123!"}


def is_authenticated():
    return session.get("logged_in") is True


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == ADMIN_USER["username"] and password == ADMIN_USER["password"]:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if not is_authenticated():
        return redirect(url_for("login"))

    return render_template("dashboard.html")


@app.route("/scan", methods=["POST"])
def scan():
    if not is_authenticated():
        return redirect(url_for("login"))

    scan_type = request.form.get("scan_type")
    target = request.form.get("target", "")
    details = {}

    if scan_type == "url":
        details = security_ai.scan_url(target)
    elif scan_type == "html":
        details = security_ai.analyze_html(target)
    elif scan_type == "password":
        details = security_ai.analyze_password(target)

    return render_template("scan_results.html", target=target, scan_type=scan_type, details=details)


if __name__ == "__main__":
    app.run(debug=True)
