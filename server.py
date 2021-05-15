#FastAPI server
import base64
import hmac
import hashlib
import json
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi import responses
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "d4e29d7a76c9780a82cad0a39bca285784879a70255fc9c7e6388e8f00becd94"
PASSWORD_SALT = "a72d7a42eb07e19d2a7d979d4a3aba3045b0ea677c0f13d35d34224d35f6e87e"

users = {
    "alexey@mail.ru" : {
        "name" : "Алексей",
        "password" : "e72dde79de66745ca05556ca17f0a75a08e896c53cbc51398a043e2bd2213fe2", # "12345678"
        "balance" : 120_000
    },
    "petr@mail.ru" : {
        "name" : "Пётр",
        "password" : "c74a05b853d98dce461cd0c0bbf19b64508ebbb699812e5cb7631b45ba44f97a", # "1234"
        "balance" : 350_000
    }
}
def sign_data(data: str) -> str:
    """ Возвращает подписанные данные data. """
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password+PASSWORD_SALT).encode()).hexdigest()
    return password_hash.lower() == users.get(username)["password"].lower()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
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

    return Response(f"Привет, {users[valid_username]['name']}<br />Баланс: {users[valid_username]['balance']}", media_type="text/html")
    # return Response(login_page, media_type="text/html")



@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data.get("username")
    password = data.get("password")
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            })
            , media_type="application/json")
    
    response = Response(
        json.dumps({
            "success": True,
            "message": f"login: {username},<br /> Баланс: {users[username]['balance']}"
        }), media_type="application/json")
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
