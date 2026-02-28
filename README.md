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
* Uses `SmtpClient` (STARTTLS) for email delivery and `FetchClient` for HTTP-based connectors (FCM, generic API).

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

NOTIFY "outbox" → on_notify(payload):
  payload = message UUID
  if !in_progress → pending_messages_.push(id)
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
created ──submit──► prepared ──send──► sending ──done──► done
                                                ──fail──► failed
```

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
      "smtp": {
        "default": {
          "host": "smtp.example.com",
          "port": 587,
          "username": "noreply@example.com",
          "password": "secret"
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
| `heartbeat` | int | `60000` | Outbox check interval in milliseconds |
| `max_in_flight` | int | `10` | Maximum concurrent message dispatches |
| `smtp` | object | — | SMTP server profiles (name → host/port/credentials) |
| `fcm` | object | — | FCM profiles (name → uri/token) |
| `api` | object | — | Generic API profiles (name → uri/auth/token) |

The process also requires:
* `postgres.helper` connection string in the config
* OAuth2 `service` credentials in `conf/oauth2/default.json`

Build requirements: `WITH_POSTGRESQL`, `WITH_SSL` — both must be enabled.

Installation
-

Follow the build and installation instructions for [Apostol (C++20)](https://github.com/apostoldevel/libapostol#build-and-installation).

[^crm]: **Apostol CRM** — a template project built on the [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) and [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform) frameworks.
