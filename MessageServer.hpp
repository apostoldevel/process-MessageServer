#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/process_module.hpp"
#include "apostol/bot_session.hpp"
#include "apostol/pg.hpp"
#include "apostol/smtp_client.hpp"
#include "apostol/fetch_client.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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

    struct MessageInfo
    {
        std::string id;
        time_point  started_at;
        std::unique_ptr<SmtpClient> smtp_client;
    };

    std::unordered_map<std::string, MessageInfo> messages_;

    // Pending message IDs from NOTIFY (processed in heartbeat)
    std::vector<std::string> pending_messages_;

    time_point   next_check_{};
    milliseconds check_interval_{60'000};  // 1 minute
    std::size_t  max_in_flight_{10};

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
    void enum_messages(std::vector<PgResult> results);

    // -- Message lifecycle ----------------------------------------------------
    void do_fetch(const std::string& id);
    void dispatch_message(const std::string& id, const PgResult& res, int row);

    void send_smtp(const std::string& id, const std::string& profile,
                   const std::string& address, const std::string& subject,
                   const std::string& content);
    void send_fcm(const std::string& id, const std::string& profile,
                  const std::string& content);
    void send_api(const std::string& id, const std::string& profile,
                  const std::string& address, const std::string& content);

    void do_send(const std::string& id);
    void do_done(const std::string& id, const std::string& msg_id = "");
    void do_fail(const std::string& id, const std::string& error);

    void delete_message(const std::string& id);
    bool in_progress(const std::string& id) const;
    bool under_limit() const;

    void on_fatal(const std::string& error);

    void load_config(Application& app);
};

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
