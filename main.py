import argparse
import asyncio
import secrets

import bcrypt
import pwinput
import os
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode
from contextlib import asynccontextmanager
from functools import partial
from multiprocessing import Pool

import pyotp
import yaml
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, Form, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from jinja2 import Environment, FileSystemLoader
from redis import asyncio as aioredis
import uvicorn

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OTP_APP")

app: FastAPI = FastAPI()
env = Environment(loader=FileSystemLoader("templates"))
index_template = env.get_template("index.html")
bad_password_template = env.get_template("bad_password.html")
otp_template = env.get_template("otp.html.j2")
predefined_bcrypt_hash = os.environ.get("PREDEFINED_HASH").encode("utf-8")
secrets_path = 'secrets.yml'
temp_session_store = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis = await aioredis.from_url("redis://redis", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis)
    yield
    await redis.close()


app.router.lifespan_context = lifespan


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_message(message: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return urlsafe_b64encode(salt + encrypted_message)


def decrypt_message(encrypted_message_with_salt: bytes, password: str) -> str:
    encrypted_message_with_salt = urlsafe_b64decode(encrypted_message_with_salt)
    salt = encrypted_message_with_salt[:16]
    encrypted_message = encrypted_message_with_salt[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()


def process_secret(password: str, secret_desc) -> dict[str, str]:
    return {
        'secret': decrypt_message(secret_desc['secret'], password),
        'name': secret_desc['name'],
    }


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=index_template.render())


@app.post("/check-password", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def check_password(password: str = Form(...)):
    start_time = time.monotonic()

    if not verify_password_hash(password):
        return HTMLResponse(content=env.get_template("bad_password.html").render(), status_code=403)

    with open(secrets_path, "r") as file:
        encrypted_secrets = yaml.safe_load(file) or []

    func = partial(process_secret, password)

    with Pool() as pool:
        decrypted_secrets = pool.map(func, encrypted_secrets)

    token = secrets.token_urlsafe(32)
    temp_session_store[token] = {
        "secrets": decrypted_secrets,
        "expires": time.monotonic() + 10
    }

    logger.info(f"Time to decrypt {len(decrypted_secrets)} secrets: {time.monotonic() - start_time:.2f}s")

    return HTMLResponse(content=otp_template.render(token=token))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    if token not in temp_session_store:
        await websocket.close(code=4401)
        return

    session = temp_session_store.pop(token)
    if time.monotonic() > session['expires']:
        await websocket.close(code=4401)
        return

    decrypted_secrets = session['secrets']

    try:
        await websocket.accept()
        timeout = 5 * 60
        start_time = time.monotonic()
        last_codes = None
        while time.monotonic() - start_time < timeout:
            otps = [{"name": entry['name'], "code": pyotp.TOTP(entry['secret']).now()} for entry in decrypted_secrets]

            if otps != last_codes:
                await websocket.send_json(otps)
                last_codes = otps

            await asyncio.sleep(0.1)
        logger.info(f'Closing connection due to timeout of {timeout} seconds')
        await websocket.close(code=4400)
    except WebSocketDisconnect:
        pass
    finally:
        for entry in decrypted_secrets:
            entry['secret'] = None
        decrypted_secrets.clear()


def verify_password_hash(password: str) -> bool:
    start_time = time.monotonic()
    result = bcrypt.checkpw(password.encode('utf-8'), predefined_bcrypt_hash)
    logger.info(f"Time verify password: {time.monotonic() - start_time:.4f}s")
    return result


def run_server(host: str, port: int):
    uvicorn.run(app, host=host, port=port, proxy_headers=True)


def add_secret():
    if not predefined_bcrypt_hash:
        print("PREDEFINED_HASH environment variable must be set with a bcrypt hash")
        return

    password = pwinput.pwinput(prompt='Enter your password: ', mask='*')

    if not verify_password_hash(password):
        print("Invalid password")
        return

    secret = pwinput.pwinput(prompt='Enter the OTP secret: ', mask='*')
    secret_name = input("Enter the secret name: ")
    secret = encrypt_message(secret, password).decode()

    with open(secrets_path, 'r') as file:
        data = yaml.safe_load(file)
    if data is None:
        data = []
    new_entry = {
        'secret': secret,
        'name': secret_name
    }
    data.append(new_entry)

    with open(secrets_path, 'w') as file:
        yaml.dump(data, file, sort_keys=False)

    print("New secret added to secrets.yml")


def remove_secret():
    secret_name = input("Enter the secret name: ")

    with open(secrets_path, 'r') as file:
        data = yaml.safe_load(file)
    if data is None:
        data = []
    entry_exists = any(entry['name'] == secret_name for entry in data)

    if entry_exists:
        data = [entry for entry in data if entry['name'] != secret_name]

        with open(secrets_path, 'w') as file:
            yaml.dump(data, file, sort_keys=False)

        print(f"Secret '{secret_name}' removed successfully!")
    else:
        print(f"No secret found with the name '{secret_name}'.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run web server or CLI command.")
    parser.add_argument('--add-secret', action='store_true', help=f'Adds secret to {secrets_path}')
    parser.add_argument('--remove-secret', action='store_true', help=f'Removes secret from {secrets_path}')
    parser.add_argument('--serve', action='store_true', help="Start the server")
    parser.add_argument('--host', type=str, default="0.0.0.0", help="Host for the server")
    parser.add_argument('--port', type=int, default=8000, help="Port for the server")

    args = parser.parse_args()

    if args.serve:
        run_server(args.host, args.port)
    elif args.add_secret:
        add_secret()
    elif args.remove_secret:
        remove_secret()
    else:
        run_server("0.0.0.0", 8000)
