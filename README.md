[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

Message Server
-
**MessageServer** is a process for [Apostol](https://github.com/apostoldevel/apostol).

Description
-
**MessageServer** is a long-running background process that delivers outbound messages from a PostgreSQL outbox table to external services. It authenticates as `apibot`, polls the message queue, and dispatches each message through the appropriate connector based on the message agent type.

The process runs independently inside the Apostol master process, sharing the same `epoll`-based event loop — no threads, no blocking I/O.

How it works
-
1. Authenticates via OAuth2 `client_credentials` as `apibot`; re-authenticates every 24 hours.
2. Subscribes to the PostgreSQL `outbox` notify channel via `LISTEN outbox`.
3. Polls `api.outbox('prepared')` every minute for queued messages.
4. For each message, fetches full details via `api.get_service_message(id)` and dispatches through the matching connector.
5. On success — calls `api.execute_object_action(id, 'done')`.
6. On failure — records the error label and calls `api.execute_object_action(id, 'fail')`.

Message agents
-
Dispatch is driven by two fields in the message record: `agenttypecode` and `agentcode`.

| Agent type | Agent code | Connector | Transport |
|------------|-----------|-----------|-----------|
| `email.agent` | `smtp.agent` | `CSMTPConnector` | SMTP email |
| `api.agent` | `fcm.agent` | `CFCMConnector` | Firebase Cloud Messaging (push notifications) |
| `api.agent` | `m2m.agent` | `CM2MConnector` | SMS via МТС Communicator (M2M API) |
| `api.agent` | `sba.agent` | `CSBAConnector` | Sberbank internet acquiring API |
| `api.agent` | _(other)_ | `CAPIConnector` | Generic HTTP API call |

Responses from HTTP API connectors are saved to the inbox via `api.add_inbox`.

Provider tokens (OAuth2 / Google service accounts) are fetched on startup and refreshed every 55 minutes.

Configuration
-
Enable the process and specify connector config files in the Apostol configuration:

```ini
[process/MessageServer]
enable=true
smtp=conf/smtp.conf      # SMTP server(s)
fcm=conf/fcm.conf        # Firebase Cloud Messaging credentials
m2m=conf/m2m.conf        # МТС Communicator (M2M) credentials
sba=conf/sba.conf        # Sberbank acquiring credentials
api=conf/api.conf        # Generic API connector settings
```

Each key under `[process/MessageServer]` (except `enable`) is treated as a profile name pointing to a connector config file. Profiles containing an `oauth2` field trigger automatic OAuth2 provider loading.

Database module
-
MessageServer is tightly coupled to the **`message`** module of [db-platform](https://github.com/apostoldevel/db-platform) (`db/sql/platform/entity/object/document/message/`).

Key database objects:

| Object | Purpose |
|--------|---------|
| `db.message` | Message record: agent, profile (sender domain/provider), address (recipient), subject, content |
| `outbox` sub-entity | Queued outbound messages with state machine; fires `NOTIFY 'outbox'` when a message enters prepared state |
| `api.outbox(state)` | Returns messages in the given state (typically `'prepared'`) |
| `api.get_service_message(id)` | Fetches full message details for dispatch |
| `api.execute_object_action(id, action)` | State transitions: `'send'`, `'done'`, `'fail'`, `'cancel'` |
| `api.add_inbox(...)` | Stores the HTTP API response as an inbound record |

Related modules
-
- **PGFetch** — HTTP client used internally by API-based connectors (FCM, M2M, SBA, generic API)

Installation
-
Follow the build and installation instructions for [Apostol](https://github.com/apostoldevel/apostol#build-and-installation).
