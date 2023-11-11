from flask import Flask, request
from flask_cors import CORS
from dotenv import load_dotenv
from os.path import join, dirname
import logging
import sys
from database import Database
from os import environ
from models.user import User
from models.token import Token

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

dotenv_path = join(dirname(__file__), ".env")
load_dotenv(dotenv_path)

Database.connect()


@app.post("/login")
def login():
    data = request.get_json()
    email = data["email"]
    password = data["password"]

    user = User.get_by_email(email)
    password_correct = user.verify_password(password)

    if not password_correct:
        return "Invalid credentials", 401

    token = user.create_token()
    user.token = token

    return user.toJSON()


@app.post("/register")
def register():
    data = request.get_json()
    first_name = data["first_name"]
    last_name = data["last_name"]
    email = data["email"]
    password = data["password"]

    user = User.create(first_name, last_name, email, password)

    if user is None:
        return "User already exists", 409

    return user.toJSON()


@app.get("/user-by-token")
def user_by_token():
    data = request.get_json()
    user_id = data["user_id"]
    token_str = data["token"]

    token = Token.get_by_str(user_id, token_str)

    if token is None:
        return "Invalid token", 401

    is_valid = token.is_valid()

    if not is_valid:
        return "Invalid token", 401

    user = User.get_by_id(user_id)

    return user.toJSON()


@app.route("/database/create")
def create_tables():
    Database.create_tables()
    return "Tables created"


@app.route("/database/drop")
def drop_tables():
    Database.drop_tables()
    return "Tables dropped"


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=environ.get("AUTH_SERVICE_PORT"),
        debug=environ.get("AUTH_SERVICE_DEBUG"),
    )
