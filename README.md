# Słowo na dziś · Word for Today

A free, self-hosted app with a Bible quote for every day, a prayer for today, the whole Bible to read and search, and a conversation that answers what you are going through with a warm reply and fitting verses.

The interface and the Bible text are available in seven languages: Polish, English, Spanish, German, French, Italian and Swedish.

## Why this app exists

There are apps on the market that do something similar: a daily verse, prayers, a companion to talk to. Many of them charge a subscription for it, around 35 zł a week, which is roughly €8 or $9 a week.

That is where the idea came from. A daily word from the Bible and a kind answer in a hard moment should not cost that much, or anything at all. So this app does the same job for free: it runs on your own computer or server, has no subscription, shows no ads, and sends nothing you type to anyone.

## Built with Claude Fable 5.2

The whole application was built by Claude Fable 5.2, Anthropic's AI model, working in Claude Code: the interface, the server, the Bible data pipeline, the conversation agent, the translations, the Docker setup and the security hardening. The idea, the direction and the review of every step came from the repository owner.

## What it does

| View | What you get |
| --- | --- |
| **Quote of the day** | One verse a day, from a hand-picked set of 164 verses, the whole New Testament or the whole Old Testament. It changes at midnight. |
| **Prayer for today** | 46 prayers taken from the Bible, a different one each time, plus three traditional Catholic prayers in Polish. |
| **My situation** | A conversation window, opened by the robot button. You describe what is going on and get a warm reply, a gentle question and Bible verses for it. |
| **Bible** | The Old and New Testament: pick the testament, book and chapter, or search for a word. Tap a verse to save it. |
| **Saved** | Every verse you saved, in one place. |
| **Account** | Sign in to keep saved verses and settings on the server and see them on every device. |

Also included:

- a second language shown alongside the main one, verse by verse
- a light and a dark theme
- a layout for phones, and a phone preview you can open on a computer
- an admin panel listing the accounts

### The conversation agent

The agent that answers in "My situation" is written in the app's own code. It uses no outside AI service, so nothing you type leaves your device.

It recognises 19 topics (fear, sadness, loneliness, tiredness, decisions, guilt, illness, doubt and others) from keywords in seven languages, remembers what was already said in the conversation, and does not repeat verses. A message about self-harm gets helpline numbers and a request to reach a real person.

It is a program, not a pastor or a therapist, and it says so. It matches keywords; it does not understand free text the way a language model does.

## Running it

### With Docker

```bash
docker compose up -d --build
```

Then open http://127.0.0.1:8000.

Settings go into a `.env` file next to `docker-compose.yml`; `.env.example` lists them all. The accounts are kept in the `slowo-data` volume and survive a restart.

### Without Docker

The server needs only Python 3.12 or newer and nothing else:

```bash
python server.py
```

On Windows, where Python is started with the `py` launcher:

```bash
py server.py
```

### As a plain file

Opening `index.html` straight from the disk also works. In that mode there is no server: accounts stay in the browser, and registration asks for no e-mail address, because no code can be sent.

## Settings

All settings are environment variables. With Docker Compose they are read from `.env`.

| Variable | Default | What it does |
| --- | --- | --- |
| `SLOWO_BIND` | `127.0.0.1` | Address the Docker port is published on. `127.0.0.1` means this computer only. |
| `SLOWO_PORT` | `8000` | Port the app is published on (Docker). |
| `HOST`, `PORT` | `127.0.0.1`, `8000` | Address and port when the server runs without Docker. |
| `SLOWO_DB` | `slowo.db` | Path of the database file. |
| `SLOWO_ADMIN` | empty | Login that gets the admin panel. Empty means the very first account. |
| `SLOWO_HOSTS` | empty | Host names the app answers to, comma-separated. Empty means any. |
| `SLOWO_SECURE` | `0` | Set to `1` behind HTTPS: cookies are then sent only over HTTPS. |
| `TRUST_PROXY` | `0` | Set to `1` behind a reverse proxy, so the visitor's real address is used. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | empty | Mail server for verification codes. Without `SMTP_HOST` the codes are printed to the server log. |

## Accounts

- Registration asks for a login, an e-mail address and a password, then sends a 6-digit code to that address. The account is created once the code is confirmed.
- A code is valid for 15 minutes. Five wrong codes end the registration. A new code can be requested once a minute, five times at most.
- The first account becomes the administrator, unless `SLOWO_ADMIN` names another login.
- A forgotten password cannot be recovered. The administrator can remove the account so it can be created again.

## Security

- Passwords are stored as scrypt hashes. Sessions are kept in HttpOnly, SameSite=Strict cookies and stored hashed.
- Every database query uses parameters, and every value sent to the server is validated.
- The server sends only the app's own files. A Content-Security-Policy allows only the page's own scripts, named by hash.
- Changes need a custom header and a same-host Origin, so another site cannot make them for a signed-in user.
- Sign-in attempts, verification codes, registrations and API requests are rate-limited.
- The Docker container runs as an unprivileged user, with a read-only file system, no Linux capabilities and limits on memory and processes.

Things to know before putting it on the internet:

- The server speaks plain HTTP. Put a reverse proxy with HTTPS in front of it and set `SLOWO_SECURE=1` and `TRUST_PROXY=1`.
- On Docker Desktop every visitor looks like the same address to the server, so the rate limits are shared by everyone. Behind a reverse proxy with `TRUST_PROXY=1` each visitor is counted separately.
- Registration tells the visitor when a login or an e-mail address is already taken.

## What is in the repository

| Path | Contents |
| --- | --- |
| `index.html` | The whole app: markup, styles, script, the hand-picked verses, the prayers and all interface text. |
| `server.py` | The server: static files and a JSON API for accounts, sessions and saved verses, on SQLite. |
| `data/nt-*.js`, `data/ot-*.js` | The New and Old Testament, one file per language, loaded when needed. |
| `vendor/bcrypt.min.js` | bcrypt.js, used for passwords when the app runs as a plain file. |
| `Dockerfile`, `docker-compose.yml`, `.env.example` | The Docker image and its settings. |

## Bible translations

All seven translations are in the public domain, which is why the language sounds old:

| Language | Translation |
| --- | --- |
| Polish | Biblia Gdańska (1881 edition) |
| English | King James Version |
| Spanish | Reina-Valera 1909 |
| German | Elberfelder 1905 |
| French | Crampon 1923 |
| Italian | Riveduta (Luzzi) |
| Swedish | Bibeln 1917 |

The app holds 23,145 verses of the Old Testament and 7,957 of the New in each language. The Old Testament has the 39 books common to all seven translations, so it does not include the deuterocanonical books.

Verse numbers follow each translation. In a few places the same number therefore points to a neighbouring verse in another language.

The texts come from the [scrollmapper/bible_databases](https://github.com/scrollmapper/bible_databases) collection and, for Italian, from getbible.net. `vendor/bcrypt.min.js` is bcrypt.js by Daniel Wirtz, released under the Apache License 2.0.
