import argparse
import bcrypt
import pwinput
import os
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode
from contextlib import asynccontextmanager
from functools import partial
from multiprocessing import Pool

import yaml
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from jinja2 import Environment, FileSystemLoader
from redis import asyncio as aioredis
import uvicorn

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
env = Environment(loader=FileSystemLoader("templates"))

predefined_bcrypt_hash = os.environ.get("PREDEFINED_HASH")
secrets_path = 'secrets.yml'


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis = await aioredis.from_url("redis://redis", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis)
    yield
    await redis.close()


app.router.lifespan_context = lifespan


def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_message(message: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return urlsafe_b64encode(salt + encrypted_message)


def decrypt_message(encrypted_message_with_salt: bytes, password: str):
    encrypted_message_with_salt = urlsafe_b64decode(encrypted_message_with_salt)
    salt = encrypted_message_with_salt[:16]
    encrypted_message = encrypted_message_with_salt[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message


def process_secret(password, secret_desc):
    secret_value = decrypt_message(secret_desc['secret'], password)
    name = secret_desc['name']
    return {
        'secret': secret_value,
        'name': name,
    }


@app.get("/", response_class=HTMLResponse)
async def index():
    template = env.get_template("index.html")
    content = template.render()
    return HTMLResponse(content=content)


@app.post("/check-password", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def check_password(password: str = Form(...)):
    start_time = time.monotonic()

    if not bcrypt.checkpw(password.encode('utf-8'), predefined_bcrypt_hash.encode('utf-8')):
        template = env.get_template("bad_password.html")
        content = template.render()
        return HTMLResponse(content=content, headers={"HX-Retarget": "#error"})

    func = partial(process_secret, password)
    with open(secrets_path, "r") as file:
        secrets = yaml.safe_load(file)

    with Pool() as pool:
        secrets_list = pool.map(func, secrets)

    template = env.get_template("otp.html.j2")
    content = template.render(secrets=secrets_list)
    logger.info(f"Time to decrypt {len(secrets_list)} secrets: {time.monotonic() - start_time:.2f}s")

    return HTMLResponse(content=content)


def run_server(host: str, port: int):
    uvicorn.run(app, host=host, port=port, proxy_headers=True)


def add_secret():
    if not predefined_bcrypt_hash:
        print("PREDEFINED_HASH environment variable must be set with a bcrypt hash")
        return

    password = pwinput.pwinput(prompt='Enter your password: ', mask='*')

    if not bcrypt.checkpw(password.encode('utf-8'), predefined_bcrypt_hash.encode('utf-8')):
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
