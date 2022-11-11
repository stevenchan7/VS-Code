import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, rp
from datetime import date

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Custom filter
app.jinja_env.filters["rp"] = rp

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///final.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():

    # Query database for user item
    income = db.execute("SELECT * FROM items WHERE user_id = ? AND type = ?", session["user_id"], "income")
    expend = db.execute("SELECT * FROM items WHERE user_id = ? AND type = ?", session["user_id"], "expend")
    income_total_row = db.execute("SELECT SUM(total) FROM items WHERE user_id = ? AND type = ?", session["user_id"], "income")
    expend_total_row = db.execute("SELECT SUM(total) FROM items WHERE user_id = ? AND type = ?", session["user_id"], "expend")
    all_total = db.execute("SELECT SUM(total) FROM items WHERE user_id = ?", session["user_id"])

    income_total = income_total_row[0]["SUM(total)"]
    expend_total = expend_total_row[0]["SUM(total)"] * -1

    for item in expend:
        item["count"] *= -1
        item["total"] *= -1

    return render_template("index.html", income=income, expend=expend, income_total=income_total, expend_total=expend_total
    , all_total=all_total)


@app.route("/register", methods=["GET", "POST"])
def register():

    # User reached route via POST
    if request.method == "POST":

        # Get user input
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Query database for username
        user_row = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username does not exist
        if len(user_row) == 1:
            if user_row[0]["username"] == username:
                return apology("username already exist", 400)

        # Ensure user input correct
        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)
        elif not confirmation:
            return apology("must provide confirmation", 400)
        elif password != confirmation:
            return apology("confirmation not match", 400)

        # Generate password hash
        password_hash = generate_password_hash(password)

        # Add user to database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)

        # Go to login page
        return redirect("/login")

    # User reached route via GET
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST
    if request.method == "POST":

        # Get user input
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure user input correct
        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)

        # Query database search user
        user_row = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exist and password is correct
        if len(user_row) != 1 or not check_password_hash(user_row[0]["hash"], password):
            return apology("invalid username/password", 400)

        # Remeber user
        session["user_id"] = user_row[0]["id"]

        # Go to home page
        return redirect("/")

    # User reached route via GET
    return render_template("login.html")


@app.route("/insert", methods=["GET", "POST"])
@login_required
def insert():

    # User reacehd route via POST
    if request.method == "POST":

        # Get user input
        item_name = request.form.get("itemName")
        item_price = request.form.get("itemPrice")
        item_count = request.form.get("itemCount")
        insert_type = request.form.get("type")

        # Ensure user input not blank
        # Already checked using bootstrap form validation

        # Insert user input into database
        if insert_type == "income":
            db.execute("INSERT INTO items(user_id, name, price, count, total, type, date) VALUES(?, ?, ?, ?, ?, ?, ?)", session["user_id"], item_name, item_price, item_count
            , float(item_price) * float(item_count), insert_type, date.today())
        else:
            db.execute("INSERT INTO items(user_id, name, price, count, total, type, date) VALUES(?, ?, ?, ?, ?, ?, ?)", session["user_id"], item_name, item_price, int(item_count) * -1
            , float(item_price) * float(item_count) * -1, insert_type, date.today())

        return redirect("/")


    # User reached route via GET
    return render_template("/insert.html")