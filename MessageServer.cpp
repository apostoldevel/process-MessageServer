#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "MessageServer/MessageServer.hpp"

#include "apostol/application.hpp"
#include "apostol/pg_utils.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

namespace apostol
{

// --- load_config -------------------------------------------------------------
//
// Read SMTP / FCM / API profiles from the module config block.
//
// Expected JSON:
//   "module": {
//     "MessageServer": {
//       "heartbeat": 60000,
//       "max_in_flight": 10,
//       "smtp": { "profile": { "host": "...", "port": 587, "username": "...", "password": "..." } },
//       "fcm":  { "profile": { "uri": "...", "token": "..." } },
//       "api":  { "profile": { "uri": "...", "auth": "Bearer", "token": "...", "content_type": "..." } }
//     }
//   }
//

void MessageServer::load_config(Application& app)
{
    auto* cfg = app.module_config("MessageServer");
    if (!cfg)
        return;

    auto& c = *cfg;

    if (c.contains("heartbeat") && c["heartbeat"].is_number())
        check_interval_ = milliseconds(c["heartbeat"].get<int>());

    if (c.contains("max_in_flight") && c["max_in_flight"].is_number_unsigned())
        max_in_flight_ = c["max_in_flight"].get<std::size_t>();

    // SMTP profiles
    if (c.contains("smtp") && c["smtp"].is_object()) {
        for (auto& [name, val] : c["smtp"].items()) {
            if (!val.is_object()) continue;
            SmtpConfig sc;
            sc.host     = val.value("host", "localhost");
            sc.port     = val.value("port", 587);
            sc.username = val.value("username", "");
            sc.password = val.value("password", "");
            smtp_configs_[name] = std::move(sc);
        }
    }

    // FCM profiles
    if (c.contains("fcm") && c["fcm"].is_object()) {
        for (auto& [name, val] : c["fcm"].items()) {
            if (!val.is_object()) continue;
            ApiProfile p;
            p.uri          = val.value("uri", "");
            p.auth         = val.value("auth", "Bearer");
            p.token        = val.value("token", "");
            p.content_type = val.value("content_type", "application/json");
            fcm_profiles_[name] = std::move(p);
        }
    }

    // Generic API profiles
    if (c.contains("api") && c["api"].is_object()) {
        for (auto& [name, val] : c["api"].items()) {
            if (!val.is_object()) continue;
            ApiProfile p;
            p.uri          = val.value("uri", "");
            p.auth         = val.value("auth", "Bearer");
            p.token        = val.value("token", "");
            p.content_type = val.value("content_type", "application/json");
            api_profiles_[name] = std::move(p);
        }
    }
}

// --- on_start ----------------------------------------------------------------

void MessageServer::on_start(EventLoop& loop, Application& app)
{
    pool_   = &app.db_pool();
    logger_ = &app.logger();
    loop_   = &loop;

    // BotSession for apibot authentication
    bot_ = std::make_unique<BotSession>(*pool_, "MessageServer/1.0", "localhost");

    auto [client_id, client_secret] = app.providers().credentials("service");
    if (!client_id.empty())
        bot_->set_credentials(std::move(client_id), std::move(client_secret));

    // FetchClient for FCM / API HTTP dispatches
    fetch_ = std::make_unique<FetchClient>(loop);

    // Subscribe to LISTEN "outbox" for immediate dispatch
    pool_->listen("outbox", [this](std::string_view /*channel*/, std::string_view payload) {
        on_notify(payload);
    });

    // Load connector configs
    load_config(app);

    logger_->notice("MessageServer started (check_interval={}ms, max_in_flight={})",
                    check_interval_.count(), max_in_flight_);
}

// --- heartbeat ---------------------------------------------------------------

void MessageServer::heartbeat(std::chrono::system_clock::time_point now)
{
    if (!bot_ || !pool_)
        return;

    bot_->refresh_if_needed();

    if (status_ == Status::stopped) {
        if (bot_->valid())
            status_ = Status::running;
        return;
    }

    // Status::running
    process_notify_queue();

    if (now >= next_check_) {
        check_outbox();
        next_check_ = now + check_interval_;
    }
}

// --- on_stop -----------------------------------------------------------------

void MessageServer::on_stop()
{
    if (pool_)
        pool_->unlisten("outbox");
    fetch_.reset();
    if (bot_)
        bot_->sign_out();
    bot_.reset();
}

// --- on_notify ---------------------------------------------------------------
//
// NOTIFY "outbox" payload is the message UUID (object::text).
// Unlike the "report" channel, it is NOT JSON.
//

void MessageServer::on_notify(std::string_view payload)
{
    std::string id(payload);
    if (!id.empty() && !in_progress(id))
        pending_messages_.push_back(std::move(id));
}

// --- process_notify_queue ----------------------------------------------------

void MessageServer::process_notify_queue()
{
    if (pending_messages_.empty())
        return;

    auto pending = std::move(pending_messages_);
    pending_messages_.clear();

    for (auto& id : pending) {
        if (!in_progress(id) && under_limit())
            do_fetch(id);
    }
}

// --- check_outbox ------------------------------------------------------------
//
// Polling fallback (every check_interval_):
//   api.authorize(session) + api.outbox('prepared') ORDER BY created
//

void MessageServer::check_outbox()
{
    if (!bot_->valid())
        return;

    auto sql = fmt::format(
        "SELECT * FROM api.authorize({});\n"
        "SELECT * FROM api.outbox('prepared') ORDER BY created",
        pq_quote_literal(bot_->session()));

    pool_->execute(sql,
        [this](std::vector<PgResult> results) {
            enum_messages(std::move(results));
        },
        [this](std::string_view error) {
            on_fatal(std::string(error));
        },
        /*quiet=*/true);
}

// --- enum_messages -----------------------------------------------------------
//
// For each message in the outbox, enqueue for fetch if not already in progress.
//

void MessageServer::enum_messages(std::vector<PgResult> results)
{
    if (results.size() < 2 || !results[1].ok())
        return;

    auto& res = results[1];
    int rows = res.rows();
    int col_id = res.column_index("id");

    if (col_id < 0)
        return;

    for (int r = 0; r < rows; ++r) {
        std::string id = res.value(r, col_id) ? res.value(r, col_id) : "";
        if (id.empty())
            continue;

        if (!in_progress(id) && under_limit())
            do_fetch(id);
    }
}

// --- do_fetch ----------------------------------------------------------------
//
// Fetch full message details:
//   api.authorize(session) + api.get_service_message(id)
// Then dispatch based on agent type.
//

void MessageServer::do_fetch(const std::string& id)
{
    if (!bot_->valid())
        return;

    messages_[id] = MessageInfo{id, std::chrono::system_clock::now(), nullptr};

    auto sql = fmt::format(
        "SELECT * FROM api.authorize({});\n"
        "SELECT * FROM api.get_service_message({}::uuid)",
        pq_quote_literal(bot_->session()),
        pq_quote_literal(id));

    pool_->execute(sql,
        [this, id](std::vector<PgResult> results) {
            if (!in_progress(id))
                return;

            if (results.size() < 2 || !results[1].ok() || results[1].rows() == 0) {
                delete_message(id);
                return;
            }

            dispatch_message(id, results[1], 0);
        },
        [this, id](std::string_view error) {
            if (in_progress(id))
                do_fail(id, std::string(error));
            else
                delete_message(id);
        });
}

// --- dispatch_message --------------------------------------------------------
//
// Route by (agenttypecode, agentcode) — mirrors v1 SendMessage().
//

void MessageServer::dispatch_message(const std::string& id, const PgResult& res, int row)
{
    int col_type    = res.column_index("agenttypecode");
    int col_agent   = res.column_index("agentcode");
    int col_profile = res.column_index("profile");
    int col_address = res.column_index("address");
    int col_subject = res.column_index("subject");
    int col_content = res.column_index("content");

    if (col_type < 0 || col_agent < 0) {
        delete_message(id);
        return;
    }

    auto safe = [&](int col) -> std::string {
        return (col >= 0 && res.value(row, col)) ? res.value(row, col) : "";
    };

    std::string type    = safe(col_type);
    std::string agent   = safe(col_agent);
    std::string profile = safe(col_profile);
    std::string address = safe(col_address);
    std::string subject = safe(col_subject);
    std::string content = safe(col_content);

    if (type == "email.agent") {
        if (agent == "smtp.agent")
            send_smtp(id, profile, address, subject, content);
        else
            delete_message(id);
    } else if (type == "api.agent") {
        if (agent == "fcm.agent")
            send_fcm(id, profile, content);
        else if (agent != "bm.agent")
            send_api(id, profile, address, content);
        else
            delete_message(id);
    } else {
        delete_message(id);
    }
}

// --- send_smtp ---------------------------------------------------------------

void MessageServer::send_smtp(const std::string& id, const std::string& profile,
                              const std::string& address, const std::string& subject,
                              const std::string& content)
{
    // Resolve SMTP config: profile may be "config_name@domain"
    auto at = profile.find('@');
    std::string config_name = (at != std::string::npos) ? profile.substr(0, at) : profile;

    auto it = smtp_configs_.find(config_name);
    if (it == smtp_configs_.end())
        it = smtp_configs_.find("default");
    if (it == smtp_configs_.end()) {
        do_fail(id, "SMTP config not found for profile: " + profile);
        return;
    }

    do_send(id);

    auto& info = messages_[id];
    info.smtp_client = std::make_unique<SmtpClient>(*loop_, it->second);

    auto& msg       = info.smtp_client->add_message();
    msg.from        = it->second.username;
    msg.to          = {address};
    msg.subject     = subject;
    msg.body        = content;
    msg.content_type = "text/html";

    msg.on_done = [this, id](const SmtpMessage& /*msg*/) {
        if (in_progress(id))
            do_done(id);
    };

    msg.on_error = [this, id](const SmtpMessage& /*msg*/, std::string_view error) {
        if (in_progress(id))
            do_fail(id, std::string(error));
    };

    info.smtp_client->send_mail();
}

// --- send_fcm ----------------------------------------------------------------

void MessageServer::send_fcm(const std::string& id, const std::string& profile,
                             const std::string& content)
{
    auto it = fcm_profiles_.find(profile);
    if (it == fcm_profiles_.end())
        it = fcm_profiles_.find("default");
    if (it == fcm_profiles_.end()) {
        do_fail(id, "FCM config not found for profile: " + profile);
        return;
    }

    auto& prof = it->second;

    if (prof.token.empty()) {
        do_fail(id, "FCM access token is empty for profile: " + profile);
        return;
    }

    std::string url = prof.uri;
    if (url.empty())
        url = fmt::format("https://fcm.googleapis.com/v1/projects/{}/messages:send", profile);

    do_send(id);

    std::vector<std::pair<std::string, std::string>> headers = {
        {"Authorization", prof.auth + " " + prof.token},
        {"Content-Type",  prof.content_type}
    };

    fetch_->post(url, content, headers,
        [this, id](FetchResponse resp) {
            if (!in_progress(id))
                return;

            if (resp.status_code >= 200 && resp.status_code < 300) {
                // Try to extract FCM message name from response
                std::string msg_id;
                try {
                    auto j = nlohmann::json::parse(resp.body);
                    if (j.contains("name") && j["name"].is_string())
                        msg_id = j["name"].get<std::string>();
                } catch (...) {}
                do_done(id, msg_id);
            } else {
                // Parse error from response
                std::string error = fmt::format("HTTP {}", resp.status_code);
                try {
                    auto j = nlohmann::json::parse(resp.body);
                    if (j.contains("error") && j["error"].is_object()) {
                        auto& err = j["error"];
                        error = fmt::format("[{}] {}: {}",
                            err.value("code", 0),
                            err.value("status", ""),
                            err.value("message", ""));
                    }
                } catch (...) {}
                do_fail(id, error);
            }
        },
        [this, id](std::string_view error) {
            if (in_progress(id))
                do_fail(id, std::string(error));
        });
}

// --- send_api ----------------------------------------------------------------

void MessageServer::send_api(const std::string& id, const std::string& profile,
                             const std::string& address, const std::string& content)
{
    auto it = api_profiles_.find(profile);
    if (it == api_profiles_.end())
        it = api_profiles_.find("default");
    if (it == api_profiles_.end()) {
        do_fail(id, "API config not found for profile: " + profile);
        return;
    }

    auto& prof = it->second;

    std::string url = prof.uri;
    if (!address.empty()) {
        if (address.front() == '/')
            url += address;
        else
            url += '/' + address;
    }

    do_send(id);

    std::vector<std::pair<std::string, std::string>> headers = {
        {"Content-Type", prof.content_type.empty() ? "application/json" : prof.content_type}
    };

    if (!prof.token.empty())
        headers.push_back({"Authorization",
                           (prof.auth.empty() ? "Bearer" : prof.auth) + " " + prof.token});

    fetch_->post(url, content, headers,
        [this, id](FetchResponse resp) {
            if (!in_progress(id))
                return;

            if (resp.status_code >= 200 && resp.status_code < 300)
                do_done(id);
            else
                do_fail(id, fmt::format("HTTP {}: {}", resp.status_code,
                                        resp.body.substr(0, 256)));
        },
        [this, id](std::string_view error) {
            if (in_progress(id))
                do_fail(id, std::string(error));
        });
}

// --- do_send -----------------------------------------------------------------
//
// Transition message state: prepared -> sending
//

void MessageServer::do_send(const std::string& id)
{
    if (!bot_->valid())
        return;

    auto sql = fmt::format(
        "SELECT * FROM api.authorize({});\n"
        "SELECT * FROM api.execute_object_action({}::uuid, {})",
        pq_quote_literal(bot_->session()),
        pq_quote_literal(id),
        pq_quote_literal("send"));

    pool_->execute(sql,
        [](std::vector<PgResult> /*results*/) {},
        [this, id](std::string_view error) {
            logger_->error("MessageServer: do_send failed for {}: {}", id, error);
        });
}

// --- do_done -----------------------------------------------------------------
//
// Message sent successfully: done + optional label (external message id).
//

void MessageServer::do_done(const std::string& id, const std::string& msg_id)
{
    logger_->debug("MessageServer: message {} sent successfully", id);

    if (!bot_->valid()) {
        delete_message(id);
        return;
    }

    std::string sql;
    if (msg_id.empty()) {
        sql = fmt::format(
            "SELECT * FROM api.authorize({});\n"
            "SELECT * FROM api.execute_object_action({}::uuid, {})",
            pq_quote_literal(bot_->session()),
            pq_quote_literal(id),
            pq_quote_literal("done"));
    } else {
        sql = fmt::format(
            "SELECT * FROM api.authorize({});\n"
            "SELECT * FROM api.set_object_label({}::uuid, {});\n"
            "SELECT * FROM api.execute_object_action({}::uuid, {})",
            pq_quote_literal(bot_->session()),
            pq_quote_literal(id), pq_quote_literal(msg_id),
            pq_quote_literal(id), pq_quote_literal("done"));
    }

    pool_->execute(sql,
        [this, id](std::vector<PgResult> /*results*/) {
            delete_message(id);
        },
        [this, id](std::string_view err) {
            logger_->error("MessageServer: do_done SQL error for {}: {}", id, err);
            delete_message(id);
        });
}

// --- do_fail -----------------------------------------------------------------

void MessageServer::do_fail(const std::string& id, const std::string& error)
{
    logger_->error("MessageServer: message {} failed: {}", id, error);

    if (!bot_->valid()) {
        delete_message(id);
        return;
    }

    auto sql = fmt::format(
        "SELECT * FROM api.authorize({});\n"
        "SELECT * FROM api.set_object_label({}::uuid, {});\n"
        "SELECT * FROM api.execute_object_action({}::uuid, {})",
        pq_quote_literal(bot_->session()),
        pq_quote_literal(id), pq_quote_literal(error),
        pq_quote_literal(id), pq_quote_literal("fail"));

    pool_->execute(sql,
        [this, id](std::vector<PgResult> /*results*/) {
            delete_message(id);
        },
        [this, id](std::string_view err) {
            logger_->error("MessageServer: do_fail SQL error for {}: {}", id, err);
            delete_message(id);
        });
}

// --- delete_message / in_progress / under_limit ------------------------------

void MessageServer::delete_message(const std::string& id)
{
    messages_.erase(id);
}

bool MessageServer::in_progress(const std::string& id) const
{
    return messages_.count(id) > 0;
}

bool MessageServer::under_limit() const
{
    return messages_.size() < max_in_flight_;
}

// --- on_fatal ----------------------------------------------------------------

void MessageServer::on_fatal(const std::string& error)
{
    status_ = Status::stopped;
    next_check_ = std::chrono::system_clock::now() + std::chrono::seconds(10);
    logger_->error("MessageServer: fatal error, pausing 10s: {}", error);
}

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
