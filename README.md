[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

Message Server
-

**Process** for **Apostol CRM**[^crm].

Description
-

**Message Server** is a background process module for the [Apostol (C++20)](https://github.com/apostoldevel/libapostol) framework. It runs as an independent forked process and delivers outbound messages from a PostgreSQL outbox table to external services (SMTP email, FCM push notifications, generic HTTP APIs).

Key characteristics:

* Written in C++20 using an asynchronous, non-blocking I/O model based on the **epoll** API.
* Connects to **PostgreSQL** via `libpq` using the `apibot` database role (helper connection pool).
* Authenticates via OAuth2 `client_credentials` grant using `BotSession`.
* **NOTIFY-driven**: subscribes to PostgreSQL `LISTEN outbox` channel for immediate dispatch.
* **Polling fallback**: checks `api.outbox('prepared')` every minute to catch missed notifications.
* **Concurrency control**: `max_in_flight` parameter bounds the number of messages being processed simultaneously, preventing overload during mass mailings.
* **Stale message cleanup**: messages stuck in-flight longer than `message_timeout` are automatically removed to prevent capacity loss.
* **Bounded NOTIFY queue**: incoming notifications are capped at `max_pending` to prevent unbounded memory growth.
* Uses `SmtpClient` (STARTTLS) for email delivery and `FetchClient` (with configurable timeout) for HTTP-based connectors (FCM, generic API).

### Architecture

Message Server follows the **ProcessModule** pattern introduced in apostol.v2:

```
Application
  └── ModuleProcess (generic process shell: signals, EventLoop, PgPool)
        └── MessageServer (ProcessModule: business logic only)
```

The process lifecycle (signal handling, crash recovery, PgPool setup, heartbeat timer) is managed by the generic `ModuleProcess` shell. `MessageServer` only contains the message dispatch logic.

### How it works

```
heartbeat (1s)
  └── BotSession::refresh_if_needed()
  └── if authenticated:
        └── process_notify_queue()  — immediate NOTIFY dispatch
        └── if now >= next_check_ (1 min):
              └── check_outbox()    — polling fallback
                    └── api.authorize(session)
                    └── api.outbox('prepared') ORDER BY created
                    └── enum_messages():
                          for each message (under concurrency limit):
                            do_fetch(id) → api.get_service_message(id)
                              └── dispatch_message(id, data)
                                    email.agent/smtp.agent → send_smtp()
                                    api.agent/fcm.agent    → send_fcm()
                                    api.agent/*            → send_api()
        └── sweep stale messages (age > message_timeout)

NOTIFY "outbox" → on_notify(payload):
  payload = message UUID
  if !in_progress && pending < max_pending → pending_messages_.push(id)
  → processed on next heartbeat
```

### Message agents

| Agent type | Agent code | Transport | v2 implementation |
|------------|-----------|-----------|-------------------|
| `email.agent` | `smtp.agent` | SMTP email | `SmtpClient` (STARTTLS) |
| `api.agent` | `fcm.agent` | Firebase Cloud Messaging | `FetchClient` HTTP POST |
| `api.agent` | _(other)_ | Generic HTTP API | `FetchClient` HTTP POST |

### Message state machine (db-platform)

```
created ──submit──► prepared ──send──► sending ──done──► submitted
                        ▲                       ──fail──► failed
                        │              repeat ◄──────────┘
                        └──────────── repeat ◄── submitted
```

One sender per message: the notify channel `outbox` in mode `single`
-

With several copies of the application, every MessageServer hears `NOTIFY outbox` and polls, and the first to read a message sends it — two copies may send one message. When the db-platform `notify` module has the channel `outbox` in mode `single` (switched per installation, when every copy is new), a new message is not a notification but a row of `notify.queue`, handed to **one** MessageServer under a token:

- a row waits in the process while `max_in_flight` messages are out; one that waited past half the channel's `lease` is given back unsent;
- the message is read in every scope of the bot session (the row carries no scope) and handled by its state: `prepared` → the action `send`, under `notify.hold` (committed only while the row is still this sender's), and the delivery starts only once `send` is **committed** (nothing leaves before it; a `send` not committed is given back unsent); `sending` — an earlier holder may have sent it: `fail`, *outcome unknown*, never sent twice; anything else — confirmed, nothing to send;
- the outcome — `notify.hold` (the row is locked first, under its token), `done` or `fail` with the label, and `notify.ack` — is **one transaction**, in the scope the message was found in. A sender whose row was handed to another is refused there (`NT409`), and what it wrote is rolled back: the message is the other sender's;
- an outcome is written before the lease runs out: a delivery out longer than `min(message_timeout, lease − 30 s)`, counted from the take (the wait for a slot included), is failed;
- there is no poll on this path: a lost wake-up is repeated by `notify.sweep`. A row closed without a confirmation is settled by the channel's `on_abandon` (`OutboxAbandon`).

On stop MessageServer takes nothing new, gives back what is not handed to a transport yet, and waits for the deliveries out (`process.stop_timeout`). One still out when the wait ends is dropped **without** being refused: it may have gone out, so its row returns by its lease and the next holder finds the message in `sending` — *outcome unknown*, not a second letter.

MessageServer reads the channel's mode every 10 s until it is `single`, and from then on keeps the subscriber; the notification path stays for messages sent before the switch (a copy that hears their notification sends them). The poll waits for the first answer of the probe of the `notify` module and then asks the channel's mode in the same statement, finding nothing once the channel is `single`: a message of the old path that missed its notification is not picked up after the switch. The path is not taken up — an error in the log — when the channel's `lease` is 30 s or shorter. It needs libapostol with `NotifySubscriber` (built `WITH_DB_PLATFORM`) and db-platform with `notify.hold`; without them only the notification path is built or used. After the switch the process leader gate `module.message-server.leader` is set to `false` by the installation: every copy runs MessageServer.

Database module
-

MessageServer is coupled to the **`message`** module of [db-platform](https://github.com/apostoldevel/db-platform).

Key database objects:

| Object | Purpose |
|--------|---------|
| `db.message` | Message record: agent, profile, address, subject, content |
| `outbox` | Sub-entity: queued outbound messages; fires `NOTIFY 'outbox'` on submit |
| `api.outbox(state)` | Returns messages in the given state (typically `'prepared'`) |
| `api.get_service_message(id)` | Fetches full message details for dispatch |
| `api.execute_object_action(id, action)` | State transitions: `'send'`, `'done'`, `'fail'` |
| `api.set_object_label(id, label)` | Store external message ID or error text |

Configuration
-

In the application config (`conf/apostol.json`):

```json
{
  "module": {
    "MessageServer": {
      "enable": true,
      "heartbeat": 60000,
      "max_in_flight": 10,
      "message_timeout": 300000,
      "max_pending": 1000,
      "fetch_timeout": 30000,
      "smtp": {
        "default": {
          "host": "smtp.example.com",
          "port": 587,
          "username": "noreply@example.com",
          "password": "secret",
          "from": "My Service <noreply@example.com>"
        }
      },
      "fcm": {
        "default": {
          "uri": "https://fcm.googleapis.com/v1/projects/my-project/messages:send",
          "token": "ya29.access-token"
        }
      },
      "api": {
        "profile_name": {
          "uri": "https://api.example.com",
          "auth": "Bearer",
          "token": "api-key",
          "content_type": "application/json"
        }
      }
    }
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable` | bool | `false` | Enable/disable the process |
| `heartbeat` | int | `60000` | Outbox polling interval in milliseconds |
| `max_in_flight` | int | `10` | Maximum concurrent message dispatches |
| `message_timeout` | int | `300000` | Stale message timeout in milliseconds (5 min). In-flight messages exceeding this age are removed to free concurrency slots. |
| `max_pending` | int | `1000` | Maximum NOTIFY queue size. Notifications arriving when the queue is full are dropped (recovered by polling fallback). |
| `fetch_timeout` | int | `30000` | HTTP timeout for FCM/API requests in milliseconds |
| `smtp` | object | — | SMTP server profiles (name → config) |
| `fcm` | object | — | FCM profiles (name → uri/token) |
| `api` | object | — | Generic API profiles (name → uri/auth/token) |

### SMTP profile fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `"localhost"` | SMTP server hostname |
| `port` | int | `587` | SMTP server port (25=plain, 587=STARTTLS, 465=implicit TLS) |
| `username` | string | — | SMTP authentication username |
| `password` | string | — | SMTP authentication password |
| `from` | string | _(username)_ | Envelope sender address. If omitted, `username` is used. |

The process also requires:
* `postgres.helper` connection string in the config
* OAuth2 `service` credentials in `conf/oauth2/default.json`

Build requirements: `WITH_POSTGRESQL`, `WITH_SSL` — both must be enabled.

Installation
-

Follow the build and installation instructions for [Apostol (C++20)](https://github.com/apostoldevel/libapostol#build-and-installation).

[^crm]: **Apostol CRM** — a template project built on the [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) and [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform) frameworks.
