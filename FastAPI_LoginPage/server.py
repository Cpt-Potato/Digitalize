import base64
import hashlib
import hmac
import json
from typing import Optional

from fastapi import Cookie, FastAPI, Form, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "4cb1f72081877a8bc1de7af2d802f571c1a9b2812027d573ab3bc72b343f1f3d"
PASSWORD_SALT = "24f99ea3689613826d06adae777000bd42200ac7f4286c12748c2ef63f343907"


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return (
        hmac.new(SECRET_KEY.encode(), msg=data.encode(), digestmod=hashlib.sha256)
        .hexdigest()
        .upper()
    )


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = (
        hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    )
    stored_password_hash = users[username]["password_hash"]
    return password_hash == stored_password_hash


users = {
    "alexey@user.com": {
        "name": "Алексей",
        "password": "some_password_1",
        "password_hash": "c153259e5e52f7face242986e820d63563db7ae4f4aa815e7a6a1f79d76727ff",
        "balance": 100_000,
    },
    "petr@user.com": {
        "name": "Пётр",
        "password": "some_password_2",
        "password_hash": "056dcaba5a20e1c7a0c6092a5239070eaaf13bee02379a7c4226303a55167bda",
        "balance": 555_555,
    },
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("templates/login.html", encoding="utf-8") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']}",
        media_type="text/html",
    )


@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({"success": False, "message": "Я вас не знаю!"}),
            media_type="application/json",
        )

    response = Response(
        json.dumps(
            {
                "success": True,
                "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}",
            }
        ),
        media_type="application/json",
    )
    username_signed = (
        f"{base64.b64encode(username.encode()).decode()}.{sign_data(username)}"
    )
    response.set_cookie(key="username", value=username_signed)
    return response
