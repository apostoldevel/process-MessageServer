#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/process_module.hpp"
#include "apostol/bot_session.hpp"
#include "apostol/pg.hpp"
#include "apostol/smtp_client.hpp"
#include "apostol/fetch_client.hpp"

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Path `single` of the notify channel `outbox` needs the db-platform subscriber;
// a libapostol without it builds the module with the path `legacy` only.
#if defined(WITH_DB_PLATFORM) && __has_include("apostol/notify_subscriber.hpp")
#include "apostol/notify_subscriber.hpp"
#define MESSAGESERVER_NOTIFY 1
#endif

namespace apostol
{

class Application;
class EventLoop;
class Logger;

// --- MessageServer -----------------------------------------------------------
//
// Background process module that delivers outbound messages from a PostgreSQL
// outbox table to external services (SMTP email, FCM push, HTTP API).
//
// Mirrors v1 CMessageServer from apostol-crm.
//
// Architecture: logic lives here (ProcessModule), injected into a generic
// ModuleProcess shell via add_custom_process(unique_ptr<ProcessModule>).
//
// Message lifecycle:
//   - Authenticates as "apibot" via OAuth2 client_credentials (BotSession)
//   - Subscribes to PostgreSQL LISTEN "outbox" channel for immediate dispatch
//   - Polls api.outbox('prepared') every minute as fallback
//   - For each message: fetches details via api.get_service_message(id)
//   - Routes by (agenttypecode, agentcode) to SMTP / FCM / generic API
//   - On success: execute_object_action(id, 'done')
//   - On failure: set_object_label(id, error) + execute_object_action(id, 'fail')
//
// Concurrency is bounded by max_in_flight_ to prevent overload during
// mass mailings (the v1 pain point).
//
// Two paths, by the mode of the notify channel `outbox` (notify.send decides
// which one a message takes; both may be live during a switch):
//
// Path `legacy` — the lifecycle above: every copy hears the NOTIFY and polls,
//   and the first to read a message sends it. The poll waits for the probe of
//   the notify module, then asks the channel's mode in the same statement and
//   finds nothing once the channel is `single`.
//
// Path `single` (T1103, E4 of T996) — a row of notify.queue, handed to one
// MessageServer:
//   heartbeat()  → until the channel is read `single`: notify.channel_policy;
//                  then a NotifySubscriber of `outbox` for the life of the
//                  process (rows are brought to their end in any mode)
//   a row        → waits here while max_in_flight messages are out; then
//                  get_service_message in every scope (the row carries no
//                  scope); by its state:
//                    prepared → `send` under notify.hold, and only once it
//                               is COMMITTED the delivery (nothing leaves
//                               before it; not committed — given back)
//                    sending  → `fail`, outcome unknown: an earlier sender may
//                               have sent it; never sent twice
//                    other    → nothing to do, confirmed
//   an outcome   → notify.hold (the row first: no deadlock with the sweep,
//                  T1147), `done` or `fail` (and the label), notify.ack — one
//                  transaction, in the scope the message was found in; under a
//                  token that is not current (NT409) it is rolled back — the
//                  row is another sender's, and so is the message
//   no poll      → a lost wake-up is the subscriber's sweep's to repeat
//
// The stop (T666, the owner's В4 — finish what is started): on_stopping takes
// nothing new and gives back what is not handed to a transport yet; busy()
// holds the stop (process.stop_timeout) while a delivery is out; on_stop
// drops what is still out — on the path single its row stays taken and
// returns by the lease (it may have gone out: never refused as unsent) —
// and only then releases the transports and the bot session.
//
// Configuration (in apostol.json):
//   "module": {
//     "MessageServer": {
//       "enable": true,
//       "heartbeat": 60000,
//       "max_in_flight": 10,
//       "smtp": {
//         "default": { "host": "smtp.host", "port": 587, "username": "...", "password": "..." }
//       },
//       "fcm": {
//         "default": { "uri": "https://fcm.googleapis.com/...", "token": "..." }
//       },
//       "api": {
//         "profile": { "uri": "https://...", "auth": "Bearer", "token": "..." }
//       }
//     }
//   }
//
class MessageServer final : public ProcessModule
{
public:
    std::string_view name() const override { return "message-server"; }

    void on_start(EventLoop& loop, Application& app) override;
    void heartbeat(std::chrono::system_clock::time_point now) override;
    void on_stopping() override;
    bool busy() const override;
    void on_stop() override;

private:
    using time_point   = std::chrono::system_clock::time_point;
    using milliseconds = std::chrono::milliseconds;

    // -- State ----------------------------------------------------------------

    PgPool*     pool_{nullptr};
    Logger*     logger_{nullptr};
    EventLoop*  loop_{nullptr};

    std::unique_ptr<BotSession> bot_;
    std::unique_ptr<FetchClient> fetch_;

    enum class Status { stopped, running };
    Status status_{Status::stopped};

    // Where a message is: read (path single, the scopes are asked); `send`
    // requested; handed to SMTP / FCM / API; outcome and ack sent (path single).
    enum class Phase { reading, sending, delivering, settling };

    struct MessageInfo
    {
        std::string id;
        std::string session;      // the scope this message was found in; act in it
        time_point  started_at;
        std::unique_ptr<SmtpClient> smtp_client;
        Phase       phase{Phase::sending};
#ifdef MESSAGESERVER_NOTIFY
        std::optional<db_platform::NotifyRow> row;   // path single: the delivery it came with
        std::size_t asks{0};                         // path single: scope reads not answered
        bool        read_failed{false};              // path single: a scope read failed
#endif
    };

    std::unordered_map<std::string, MessageInfo> messages_;

    // Pending message IDs from NOTIFY (processed in heartbeat)
    std::vector<std::string> pending_messages_;

    time_point   next_check_{};
    milliseconds check_interval_{60'000};  // 1 minute
    milliseconds message_timeout_{300'000}; // 5 minutes — stale message cleanup
    std::size_t  max_in_flight_{10};
    std::size_t  max_pending_{1000};
    long         fetch_timeout_ms_{30'000}; // 30s HTTP timeout for FCM/API

    // -- SMTP configs (profile name -> SmtpConfig) ----------------------------
    std::unordered_map<std::string, SmtpConfig> smtp_configs_;

    // -- HTTP connector config ------------------------------------------------
    struct ApiProfile
    {
        std::string uri;
        std::string auth;           // "Bearer" etc.
        std::string token;
        std::string content_type;   // "application/json" default
    };

    std::unordered_map<std::string, ApiProfile> fcm_profiles_;
    std::unordered_map<std::string, ApiProfile> api_profiles_;

    // -- NOTIFY ---------------------------------------------------------------
    void on_notify(std::string_view payload);
    void process_notify_queue();

    // -- Polling fallback -----------------------------------------------------
    void check_outbox();
    void enum_messages(const std::string& session, std::vector<PgResult> results);

    // -- Message lifecycle ----------------------------------------------------
    void do_fetch(const std::string& session, const std::string& id);

    /// The session a message was found under, or the first if no longer tracked.
    std::string message_session(const std::string& id) const;
    void dispatch_message(const std::string& id, const PgResult& res, int row);

    void send_smtp(const std::string& id, const std::string& profile,
                   const std::string& address, const std::string& subject,
                   const std::string& content);
    void send_fcm(const std::string& id, const std::string& profile,
                  const std::string& content);
    void send_api(const std::string& id, const std::string& profile,
                  const std::string& address, const std::string& content);

    /// `send`; @p deliver starts the delivery — at once on the path legacy, once
    /// `send` is committed on the path single.
    void do_send(const std::string& id, std::function<void()> deliver);
    void do_done(const std::string& id, const std::string& msg_id = "");
    void do_fail(const std::string& id, const std::string& error);

    void delete_message(const std::string& id);
    /// A message there is nothing to deliver for: forgotten (legacy), confirmed (single).
    void drop_message(const std::string& id);
    bool in_progress(const std::string& id) const;
    /// In flight and its outcome not written yet: a transport's answer is still wanted.
    bool awaiting(const std::string& id) const;
    bool under_limit() const;

    bool stopping_{false};

#ifdef MESSAGESERVER_NOTIFY
    // -- Path single ----------------------------------------------------------
    void probe_notify();
    void read_mode();
    void start_notify();
    void on_row(const db_platform::NotifyRow& row);
    void start_waiting();
    void read_single(const db_platform::NotifyRow& row, std::chrono::steady_clock::time_point taken);
    void dispatch_single(const std::string& id, const PgResult& res);
    void settle_single(const std::string& id, std::string sql);
    void settle_again(const std::string& id, const db_platform::NotifyRow& row, std::string sql);
    void settle_stale(const std::string& id, const db_platform::NotifyRow& row, std::string sql);
    void give_back(const std::string& id, std::string_view reason);
    void stop_notify();
    bool single(const std::string& id) const;
    milliseconds single_timeout() const;
    std::string outcome_sql(const std::string& id, std::string_view action, const std::string& label) const;

    std::string node_;
    std::unique_ptr<db_platform::NotifySubscriber> notify_;
    bool        notify_possible_{false};  // the database has the notify module
    bool        probing_{false};
    bool        probed_{false};           // the probe answered: the poll knows its filter
    bool        reading_mode_{false};
    std::chrono::steady_clock::time_point next_probe_{};
    std::chrono::steady_clock::time_point next_mode_{};
    std::chrono::seconds lease_{0};        // of the channel outbox, read with its mode
    long        refused_lease_{-1};        // the lease last refused, said once

    // Rows taken while max_in_flight messages are out.
    struct Waiting
    {
        db_platform::NotifyRow row;
        std::chrono::steady_clock::time_point taken;
    };
    std::deque<Waiting> waiting_;
#endif

    void on_fatal(const std::string& error);

    void load_config(Application& app);
};

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
