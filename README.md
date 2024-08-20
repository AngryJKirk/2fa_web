# 2fa in web

![](https://storozhenko.dev/no_auth/example.gif)
## Purpose

Since Authy discontinued their desktop application I was struggling finding a replacement.

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

Whenever you input the right password on the fronted, OTP keys are decrypted using your password as a key and sent to
you via HTTP.

When you close or update your page, decrypted data disappears.

The unencrypted keys are part of the Javascript built in the `<script></script>` tag. I don't know how secure that is,
but I guess it's not, so your extensions might get your data.

## Usage

1) clone the project
2) Hash your password using SHA256 (`echo -n YOUR_SECRET_PASSWORD | sha256sum`)
3) Put it in the `PREDEFINED_HASH` variable in ./docker-compose.yml
4) run `docker compose up -d`
5) run `docker compose exec app python3 main.py --add-secret` to add a secret. Make sure that you use base32 secret, but
   it is pretty much standard, so I believe in you! Also, your password *must* match the one you used for
   `PREDEFINED_HASH`
6) Open `http://localhost:11211` and enter your password. You will see your OTP codes.

### Important notes

Run `docker compose exec app python3 main.py --remove-secret` to remove a secret.

`docker-compose.yml` is set up to listen only localhost. It's *HIGHLY* recommended to put it behind the reverse proxy.
I recommend [Caddy](https://caddyserver.com/) since it has HTTPS support out of the box.

*NEVER USE THIS TOOL WITHOUT HTTPS*

### Limitations

This solution supports only SHA1 6 digit OTPs.

PRs to support more are welcome, I am too lazy. Especially because all 30 of my OTPs are using SHA1 6 digit scheme.

Due to my poor coding, secret names must be a valid JS variables, meaning it can contain only English letters,
underscores and numbers.


### Importing your keys

The hard part is exporting your keys from Authy or other services.
You should google how to do it with your current setup.

Most good tools support export, but Authy or Google Authenticator requires some effort.


