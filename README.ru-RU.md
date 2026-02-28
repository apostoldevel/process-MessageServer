[![en](https://img.shields.io/badge/lang-en-green.svg)](README.md)

Сервер сообщений
-

**Процесс** для [Apostol](https://github.com/apostoldevel/apostol) + [db-platform](https://github.com/apostoldevel/db-platform) — **Apostol CRM**[^crm].

Описание
-

**Сервер сообщений** — фоновый процесс-модуль для фреймворка [Апостол](https://github.com/apostoldevel/apostol). Запускается как отдельный форкнутый процесс и доставляет исходящие сообщения из PostgreSQL-таблицы outbox на внешние сервисы (SMTP email, FCM push-уведомления, HTTP API).

Основные характеристики:

* Написан на C++20 с использованием асинхронной неблокирующей модели ввода-вывода на базе **epoll** API.
* Подключается к **PostgreSQL** через `libpq`, используя роль `apibot` (пул соединений helper).
* Аутентифицируется через OAuth2 `client_credentials` с помощью `BotSession`.
* **NOTIFY-driven**: подписывается на PostgreSQL-канал `LISTEN outbox` для немедленной обработки.
* **Polling-fallback**: каждую минуту проверяет `api.outbox('prepared')` для обнаружения пропущенных уведомлений.
* **Контроль параллелизма**: параметр `max_in_flight` ограничивает количество одновременно обрабатываемых сообщений, предотвращая перегрузку при массовых рассылках.
* Использует `SmtpClient` (STARTTLS) для доставки email и `FetchClient` для HTTP-коннекторов (FCM, generic API).

### Архитектура

Сервер сообщений следует паттерну **ProcessModule**, введённому в apostol.v2:

```
Application
  └── ModuleProcess (generic-оболочка процесса: сигналы, EventLoop, PgPool)
        └── MessageServer (ProcessModule: только бизнес-логика)
```

Жизненный цикл процесса (обработка сигналов, crash recovery, настройка PgPool, таймер heartbeat) управляется generic-оболочкой `ModuleProcess`. `MessageServer` содержит только логику доставки сообщений.

### Как это работает

```
heartbeat (1 сек)
  └── BotSession::refresh_if_needed()
  └── если аутентифицирован:
        └── process_notify_queue()  — немедленная обработка NOTIFY
        └── если now >= next_check_ (1 мин):
              └── check_outbox()    — polling-fallback
                    └── api.authorize(session)
                    └── api.outbox('prepared') ORDER BY created
                    └── enum_messages():
                          для каждого сообщения (в пределах лимита параллелизма):
                            do_fetch(id) → api.get_service_message(id)
                              └── dispatch_message(id, data)
                                    email.agent/smtp.agent → send_smtp()
                                    api.agent/fcm.agent    → send_fcm()
                                    api.agent/*            → send_api()

NOTIFY "outbox" → on_notify(payload):
  payload = UUID сообщения
  если !in_progress → pending_messages_.push(id)
  → обрабатывается на следующем heartbeat
```

### Агенты сообщений

| Тип агента | Код агента | Транспорт | Реализация v2 |
|------------|-----------|-----------|---------------|
| `email.agent` | `smtp.agent` | SMTP email | `SmtpClient` (STARTTLS) |
| `api.agent` | `fcm.agent` | Firebase Cloud Messaging | `FetchClient` HTTP POST |
| `api.agent` | _(другие)_ | Общий HTTP API | `FetchClient` HTTP POST |

### Машина состояний сообщения (db-platform)

```
created ──submit──► prepared ──send──► sending ──done──► done
                                                ──fail──► failed
```

Модуль базы данных
-

MessageServer связан с модулем **`message`** платформы [db-platform](https://github.com/apostoldevel/db-platform).

Ключевые объекты базы данных:

| Объект | Назначение |
|--------|-----------|
| `db.message` | Запись сообщения: агент, профиль, адрес, тема, содержание |
| `outbox` | Под-сущность: очередь исходящих; отправляет `NOTIFY 'outbox'` при submit |
| `api.outbox(state)` | Возвращает сообщения в заданном состоянии (обычно `'prepared'`) |
| `api.get_service_message(id)` | Получает полные данные сообщения для отправки |
| `api.execute_object_action(id, action)` | Переходы состояний: `'send'`, `'done'`, `'fail'` |
| `api.set_object_label(id, label)` | Сохранить внешний ID сообщения или текст ошибки |

Конфигурация
-

В конфигурационном файле приложения (`conf/apostol.json`):

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

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `enable` | bool | `false` | Включить/отключить процесс |
| `heartbeat` | int | `60000` | Интервал проверки outbox в миллисекундах |
| `max_in_flight` | int | `10` | Максимум одновременных отправок |
| `smtp` | object | — | Профили SMTP-серверов (имя → host/port/credentials) |
| `fcm` | object | — | Профили FCM (имя → uri/token) |
| `api` | object | — | Профили generic API (имя → uri/auth/token) |

Также необходимы:
* Строка подключения `postgres.helper` в конфигурации
* Учётные данные OAuth2 `service` в файле `conf/oauth2/default.json`

Требования к сборке: `WITH_POSTGRESQL`, `WITH_SSL` — оба должны быть включены.

Установка
-

Следуйте указаниям по сборке и установке [Апостол](https://github.com/apostoldevel/apostol#building-and-installation).

[^crm]: **Apostol CRM** — абстрактный термин, а не самостоятельный продукт. Он обозначает любой проект, в котором совместно используются фреймворк [Apostol](https://github.com/apostoldevel/apostol) (C++) и [db-platform](https://github.com/apostoldevel/db-platform) через специально разработанные модули и процессы. Каждый фреймворк можно использовать независимо; вместе они образуют полноценную backend-платформу.
