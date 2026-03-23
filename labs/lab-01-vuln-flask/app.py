#!/usr/bin/env python3
"""
LAB-01: Deliberately Vulnerable Flask Application
Tests: SQLi, XSS, IDOR, Hardcoded creds, SSTI, SSRF
DO NOT DEPLOY — for skill testing only
"""
from flask import Flask, request, render_template_string, redirect
import sqlite3, requests, os

app = Flask(__name__)
SECRET_KEY = "hardcoded-super-secret-123"        # VULN: hardcoded secret
DB_PASSWORD = "admin:password123"                  # VULN: hardcoded cred
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"                   # VULN: AWS key pattern

@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = sqlite3.connect("users.db")
    # VULN: SQL injection — unsanitized input in query
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    results = conn.execute(sql).fetchall()
    return str(results)

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # VULN: SSTI — user input rendered as template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

@app.route("/user/<int:user_id>")
def get_user(user_id):
    # VULN: IDOR — no authorization check, any user can access any profile
    conn = sqlite3.connect("users.db")
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return str(user)

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # VULN: SSRF — fetches any URL including internal services
    resp = requests.get(url, timeout=5)
    return resp.text

@app.route("/comment", methods=["POST"])
def comment():
    text = request.form.get("text", "")
    # VULN: Stored XSS — unsanitized input stored and reflected
    return f"<div>{text}</div>"

if __name__ == "__main__":
    app.run(debug=True)  # VULN: debug mode in production
