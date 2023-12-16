from flask import request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from os.path import join, dirname
from database import Database
from os import environ
from models.user import User
from models.token import Token
from health import Health
from metrics import Metrics
import logging, graypy
from uuid import uuid4
from pydantic import BaseModel
from flask_openapi3 import OpenAPI, Info, Tag

info = Info(title="Preceni auth", version="1.0.0", description="Preceni auth API")
app = OpenAPI(__name__, info=info)
CORS(app)  # Enable CORS for all routes

# Logging
graylog_handler = graypy.GELFUDPHandler("logs.meteo.pileus.si", 12201)
environment = "dev" if environ.get("AUTH_SERVICE_DEBUG") else "prod"
graylog_handler.setFormatter(
    logging.Formatter(f"preceni-auth {environment} %(asctime)s %(levelname)s %(name)s %(message)s")
)
app.logger.addHandler(graylog_handler)
app.logger.setLevel(logging.INFO)

dotenv_path = join(dirname(__file__), ".env")
load_dotenv(dotenv_path)

Database.connect()
app.logger.info("Connected to database")

auth_tag = Tag(name="auth", description="Authentication")
health_tag = Tag(name="health", description="Health and metrics")


class UserResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str


@app.post("/login", tags=[auth_tag], summary="Login", responses={200: UserResponse})
def login():
    uuid = uuid4()
    app.logger.info(f"START: POST /login [{uuid}]")
    data = request.get_json()
    email = data["email"]
    password = data["password"]

    user = User.get_by_email(email)
    password_correct = user.verify_password(password)

    if not password_correct:
        return "Invalid credentials", 401

    token = user.create_token()
    user.token = token

    app.logger.info(f"END: POST /login [{uuid}]")

    return user.toJSON()


@app.post("/auth/register", tags=[auth_tag], summary="Register new user", responses={200: UserResponse})
def register():
    uuid = uuid4()
    app.logger.info(f"START: POST /register [{uuid}]")
    data = request.get_json()
    first_name = data["first_name"]
    last_name = data["last_name"]
    email = data["email"]
    password = data["password"]

    user = User.create(first_name, last_name, email, password)

    if user is None:
        return "User already exists", 409

    app.logger.info(f"END: POST /register [{uuid}]")

    return user.toJSON()


@app.get("/auth/user-by-token", tags=[auth_tag], summary="Get user by token", responses={200: UserResponse})
def user_by_token():
    uuid = uuid4()
    app.logger.info(f"START: GET /user-by-token [{uuid}]")
    user_id = request.args.get("user_id")
    token_str = request.args.get("token")

    token = Token.get_by_str(user_id, token_str)

    if token is None:
        return "Invalid token", 401

    is_valid = token.is_valid()

    if not is_valid:
        return "Invalid token", 401

    user = User.get_by_id(user_id)

    app.logger.info(f"END: GET /user-by-token [{uuid}]")

    return user.toJSON()


@app.get("/auth/metrics", tags=[health_tag], summary="Get metrics")
def metrics():
    app.logger.info("GET: Metrics")
    metrics = Metrics.get_metrics()

    response = ""
    for metric in metrics:
        response += f"{metric.name} {metric.value}\n"

    return response


@app.get("/auth/health/live", tags=[health_tag], summary="Health live check")
def health_live():
    app.logger.info("GET: Health live check")
    status, checks = Health.check_health()
    code = 200 if status == "UP" else 503

    return jsonify({"status": status, "checks": checks}), code


@app.put("/auth/health/test/toggle", tags=[health_tag], summary="Health test toggle")
def health_test():
    app.logger.info("PUT: Health test toggle")
    Health.force_fail = not Health.force_fail

    return Health.checkTest()


if __name__ == "__main__":
    Metrics.init()
    app.run(
        host="0.0.0.0",
        port=environ.get("AUTH_SERVICE_PORT"),
        debug=environ.get("AUTH_SERVICE_DEBUG"),
    )
