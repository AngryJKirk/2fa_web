# 2fa in web

![](https://storozhenko.dev/no_auth/example.gif)

## Purpose

Since Authy discontinued their desktop application I was struggling to find a replacement.

Everything I tried is bulky and overcomplicated.

I decided to make my own.

## How does it look?

It's a simple password-protected page where you can see all your 2FA codes updating in real time.

It does not have any controls on the frontend.

## Security

I tried to make it as secure as possible.

But,

1) I am no security expert.
2) I am no python or web expert.

So you *must* consider this project as insecure.

## Security implementation

OTP secrets are stored encrypted in yaml file.
They are encrypted by [Fernet](https://cryptography.io/en/latest/fernet/)

Whenever you input the right password on the frontend, OTP keys are decrypted and stored on the server side.
You are getting a new page with a short living token that is used to establish WebSocket connection.
The server sends you the OTP values (secrets are never exposed) every time they are updated.

When the WebSocket connection is shut down (like you closed the tab, refreshed the page or you hit the 5 minute
treshold) the decrypted secrets are erased from the memory of the server.

The short living token used to establish a WebSocket connection lives just 10 seconds and allows to create only a single
connection.

The security is achived by not exposing any secrets to the client and server has it unencrypted only during the session.

## Usage

1) clone the project
2) Hash your password using Bcrypt algorithm
3) Create `.env` file like `.env_example`
3) Put the hash in the `PREDEFINED_HASH` variable in the `.env` file
4) run `docker compose up -d`
5) run `docker compose exec app python3 main.py --add-secret` to add a secret. Make sure that you use base32 secret, but
   it is pretty much standard, so I believe in you! Also, your password **must** match the one you used for
   `PREDEFINED_HASH`
6) Open `http://localhost:11211` and enter your password. You will see your OTP codes.

### Important notes

Run `docker compose exec app python3 main.py --remove-secret` to remove a secret.

`docker-compose.yml` is set up to listen only localhost. It's **HIGHLY** recommended to put it behind the reverse proxy.
I recommend [Caddy](https://caddyserver.com/) since it has HTTPS support out of the box.

**NEVER USE THIS TOOL WITHOUT HTTPS**

### Configuration and Limitations

The tool supports most common algorithms but only 30 seconds based TOTPs.

The configuration available:

| Env variable      | Description                                                                        | Optionality |
|-------------------|------------------------------------------------------------------------------------|-------------|
| `PREDEFINED_HASH` | Bcrypt hash which represents your password to access the codes                     | ❌           |
| `URL_PREFIX`      | To host it somewhere like www.example.com/my_totp                                  | ✅           |
| `HOST_IP`         | To listen a different IP in `docker-compose.yml`, if for example you use Wireguard | ✅           |

### Importing your keys

The hard part is exporting your keys from Authy or other services.
You should google how to do it with your current setup.

Most good tools support export, but Authy or Google Authenticator requires some effort.


