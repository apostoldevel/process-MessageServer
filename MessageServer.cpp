#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "MessageServer/MessageServer.hpp"

#include "apostol/application.hpp"
#include "apostol/pg_utils.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>

namespace apostol
{

static constexpr const char* kFcmUrlTemplate =
    "https://fcm.googleapis.com/v1/projects/{}/messages:send";

#ifdef MESSAGESERVER_NOTIFY
namespace
{

// How often the mode of the channel is read until it is single, and how often
// a database without the notify module is asked again (a patch may arrive).
constexpr auto mode_every  = std::chrono::seconds(10);
constexpr auto probe_every = std::chrono::seconds(60);

// The outcome of a delivery is written this long before the lease of its row
// runs out: written later, it would meet the row closed (orphaned) and be
// rolled back with the refused confirmation.
constexpr auto lease_margin = std::chrono::seconds(30);

// An outcome written over the row: notify.hold takes the row of the queue
// first, under its token, so the locks go "row, then the object" — the order
// of notify.sweep, which closes the row and then calls the producer on the
// object. "Object, then row" (the ack libapostol appends last) deadlocks with
// it at the end of the lease (T1147). The hold is in the batch of the outcome
// and its ack — one transaction —, or the lock is gone before the outcome.
// A stale token is NT409 here, before anything is written.
std::string held(const db_platform::NotifyRow& row, std::string sql)
{
    if (sql.empty())
        return sql;
    return fmt::format("SELECT notify.hold({}, {});\n", row.id, row.token) + sql;
}

} // namespace
#endif

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

    if (c.contains("message_timeout") && c["message_timeout"].is_number())
        message_timeout_ = milliseconds(c["message_timeout"].get<int>());

    if (c.contains("max_pending") && c["max_pending"].is_number_unsigned())
        max_pending_ = c["max_pending"].get<std::size_t>();

    if (c.contains("fetch_timeout") && c["fetch_timeout"].is_number())
        fetch_timeout_ms_ = c["fetch_timeout"].get<long>();

    // SMTP profiles
    if (c.contains("smtp") && c["smtp"].is_object()) {
        for (auto& [name, val] : c["smtp"].items()) {
            if (!val.is_object()) continue;
            SmtpConfig sc;
            sc.host     = val.value("host", "localhost");
            sc.port     = val.value("port", 587);
            sc.username = val.value("username", "");
            sc.password = val.value("password", "");
            sc.from     = val.value("from", "");
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
#ifdef MESSAGESERVER_NOTIFY
    node_   = app.node_id();
#endif

    // BotSession for apibot authentication
    bot_ = std::make_unique<BotSession>(*pool_, "MessageServer/2.0", "127.0.0.1");

    auto [client_id, client_secret] = app.providers().credentials("service");
    if (!client_id.empty())
        bot_->set_credentials(std::move(client_id), std::move(client_secret));

    // FetchClient for FCM / API HTTP dispatches
    fetch_ = std::make_unique<FetchClient>(loop);

    // Load connector configs (must be before set_timeout — fetch_timeout_ms_ loaded here)
    load_config(app);

    fetch_->set_timeout(fetch_timeout_ms_);

    // Subscribe to LISTEN "outbox" for immediate dispatch
    pool_->listen("outbox", [this](std::string_view /*channel*/, std::string_view payload) {
        on_notify(payload);
    });

    logger_->notice("MessageServer started (check_interval={}ms, max_in_flight={}, fetch_timeout={}ms)",
                    check_interval_.count(), max_in_flight_, fetch_timeout_ms_);
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

#ifdef MESSAGESERVER_NOTIFY
    const auto steady = std::chrono::steady_clock::now();
    if (!notify_possible_ && !probing_ && steady >= next_probe_)
        probe_notify();
    else if (notify_possible_ && !notify_ && !reading_mode_ && steady >= next_mode_)
        read_mode();

    if (notify_)
        start_waiting();
#endif

#ifdef MESSAGESERVER_NOTIFY
    // Until the probe has answered the poll does not know whether to ask the
    // mode: unfiltered, right after a start, it would read the `prepared`
    // messages whose rows another copy holds, and send them beside it.
    const bool may_poll = probed_;
#else
    const bool may_poll = true;
#endif
    if (may_poll && now >= next_check_) {
        check_outbox();
        next_check_ = now + check_interval_;
    }

#ifdef MESSAGESERVER_NOTIFY
    // Path single: an outcome is written under the row's token, before its
    // lease runs out; a message still being read is given back, unsent.
    // Collected first: both change messages_.
    std::vector<std::string> overdue, unread;
    for (const auto& [id, info] : messages_) {
        if (!info.row || info.phase == Phase::settling)
            continue;
        if (now - info.started_at <= single_timeout())
            continue;
        (info.phase == Phase::reading ? unread : overdue).push_back(id);
    }
    for (const auto& id : unread) {
        logger_->warn("MessageServer: message {} not read in {}ms — given back, unsent", id, single_timeout().count());
        give_back(id, "unsent: the message was not read in time");
    }
    for (const auto& id : overdue) {
        logger_->warn("MessageServer: message {} timed out after {}ms, marking failed", id, single_timeout().count());
        do_fail(id, "Message processing timeout");
    }
#endif

    // Sweep stale messages that exceeded timeout (PG callback lost, etc.)
    for (auto it = messages_.begin(); it != messages_.end(); ) {
#ifdef MESSAGESERVER_NOTIFY
        if (it->second.row) {
            ++it;   // above
            continue;
        }
#endif
        auto age = std::chrono::duration_cast<milliseconds>(now - it->second.started_at);
        if (age > message_timeout_) {
            logger_->warn("MessageServer: message {} timed out after {}ms, marking failed",
                             it->first, age.count());
            // Mark as failed in DB before removing from memory
            if (bot_ && bot_->valid()) {
                do_fail(it->first, "Message processing timeout");
            }
            it = messages_.erase(it);
        } else {
            ++it;
        }
    }
}

// --- on_stopping / busy -----------------------------------------------------
//
// Finish what is started (T666, the owner's В4): nothing new is taken — the
// heartbeat that would start it is not called from here on —, and on the path
// single what is not handed to a transport yet goes back to the queue for
// another copy. A message whose `send` is requested goes on: its delivery
// starts when `send` is committed, and the stop waits for it.

void MessageServer::on_stopping()
{
    stopping_ = true;

#ifdef MESSAGESERVER_NOTIFY
    if (!notify_)
        return;

    // Not chosen as an addressee any more, nothing new taken.
    notify_->drain();

    while (!waiting_.empty()) {
        notify_->refuse(waiting_.front().row, "unsent: stopping, not started");
        waiting_.pop_front();
    }

    std::vector<std::string> unread;
    for (const auto& [id, info] : messages_) {
        if (info.row && info.phase == Phase::reading)
            unread.push_back(id);
    }
    for (const auto& id : unread)
        give_back(id, "unsent: stopping, not sent yet");
#endif
}

// A delivery requested or out: its outcome is the far end's, and the stop
// waits for it (up to process.stop_timeout). An outcome being written is the
// pool's to wait for.
bool MessageServer::busy() const
{
    return std::any_of(messages_.begin(), messages_.end(), [](const auto& m) {
        return m.second.phase == Phase::sending || m.second.phase == Phase::delivering;
    });
}

// --- on_stop -----------------------------------------------------------------
//
// What is still out when the stop timeout ends is dropped here: its answer
// would come into a module without a bot session (T666). The SMTP clients go
// first, with the callbacks they hold, then the HTTP client, then the bot.
// On the path single such a message's row stays taken and returns by its
// lease — never refused as unsent: it may have gone out.

void MessageServer::on_stop()
{
    if (pool_)
        pool_->unlisten("outbox");

#ifdef MESSAGESERVER_NOTIFY
    stop_notify();
#endif

    if (!messages_.empty())
        logger_->warn("MessageServer: stopping with {} message(s) unfinished — dropped; on the path single "
                      "each row returns by its lease", messages_.size());

    messages_.clear();
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
    if (!id.empty() && !in_progress(id) && pending_messages_.size() < max_pending_)
        pending_messages_.push_back(std::move(id));
}

// --- process_notify_queue ----------------------------------------------------

void MessageServer::process_notify_queue()
{
    if (pending_messages_.empty())
        return;

    auto pending = std::move(pending_messages_);
    pending_messages_.clear();

    // The message notification carries no session — pg_notify('message', …) names
    // the message, not the scope — so ask every scope, as v1 did by creating a
    // handler per session. Only the one that finds the row takes the message on;
    // the others see no rows and drop out.
    for (auto& id : pending) {
        if (in_progress(id) || !under_limit())
            continue;

        for (const auto& session : bot_->sessions())
            do_fetch(session, id);
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

    // One pass per scope: api.outbox answers within the authorized session's scope,
    // so a single pass under the first session leaves every other scope's outbox
    // unsent. v1 looped over api.get_sessions; the port kept one.
    // The poll goes around the claim of the path single: a message whose row
    // another copy holds is `prepared` until its `send` commits, and a poll
    // reading it then would send it twice. With the notify module the mode is
    // asked in the same statement — a channel switched to single makes the
    // poll empty at once, not after the next reading of the mode.
#ifdef MESSAGESERVER_NOTIFY
    const char* filter = notify_possible_
        ? " WHERE (SELECT mode FROM notify.channel_policy('outbox')) IS DISTINCT FROM 'single'"
        : "";
#else
    const char* filter = "";
#endif

    for (const auto& session : bot_->sessions()) {
        auto sql = fmt::format(
            "SELECT * FROM api.authorize({});\n"
            "SELECT * FROM api.outbox('prepared'){} ORDER BY created",
            pq_quote_literal(session), filter);

        pool_->execute(sql,
            [this, session](std::vector<PgResult> results) {
                enum_messages(session, std::move(results));
            },
            [this](std::string_view error) {
                on_fatal(std::string(error));
            },
            /*quiet=*/true);
    }
}

// --- enum_messages -----------------------------------------------------------
//
// For each message in the outbox, enqueue for fetch if not already in progress.
//

void MessageServer::enum_messages(const std::string& session, std::vector<PgResult> results)
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
            do_fetch(session, id);
    }
}

// --- do_fetch ----------------------------------------------------------------
//
// Fetch full message details:
//   api.authorize(session) + api.get_service_message(id)
// Then dispatch based on agent type.
//

void MessageServer::do_fetch(const std::string& session, const std::string& id)
{
    if (!bot_ || !bot_->valid())
        return;

    // Not registered yet. Several scopes may be asked about the same message at
    // once (see process_notify_queue), and only the one that finds it may claim it —
    // registering up front would let the first answer, whichever it was, delete the
    // work the finder is about to do.
    auto sql = fmt::format(
        "SELECT * FROM api.authorize({});\n"
        "SELECT * FROM api.get_service_message({}::uuid)",
        pq_quote_literal(session),
        pq_quote_literal(id));

    // quiet: the statement carries a session code. PgPool prints statement
    // text at debug into postgres.log — inside the container, readable
    // by any process there.
    pool_->execute(sql,
        [this, id, session](std::vector<PgResult> results) {
            if (results.size() < 2 || !results[1].ok() || results[1].rows() == 0)
                return;   // not in this scope — another one has it, or nobody has

            if (in_progress(id))
                return;   // another scope got there first

            auto& info      = messages_[id];
            info.id         = id;
            info.session    = session;
            info.started_at = std::chrono::system_clock::now();

            dispatch_message(id, results[1], 0);
        },
        [this, id](std::string_view error) {
            if (in_progress(id))
                do_fail(id, std::string(error));
            else
                delete_message(id);
        },
        /*quiet=*/true);
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
        drop_message(id);
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
            drop_message(id);
    } else if (type == "api.agent") {
        if (agent == "fcm.agent")
            send_fcm(id, profile, content);
        else if (agent != "bm.agent")
            send_api(id, profile, address, content);
        else
            drop_message(id);
    } else {
        drop_message(id);
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

    // smtp_configs_ is not changed after load_config: the reference outlives
    // the wait for `send`.
    const SmtpConfig& config = it->second;

    do_send(id, [this, id, &config, address, subject, content] {
        auto mi = messages_.find(id);
        if (mi == messages_.end())
            return;

        auto& info = mi->second;
        info.phase = Phase::delivering;
        info.smtp_client = std::make_unique<SmtpClient>(*loop_, config);

        auto& msg       = info.smtp_client->add_message();
        msg.from        = config.from.empty() ? config.username : config.from;
        msg.to          = {address};
        msg.subject     = subject;
        msg.body        = content;
        msg.content_type = "text/html";

        msg.on_done = [this, id](const SmtpMessage& /*msg*/) {
            if (awaiting(id))
                do_done(id);
        };

        msg.on_error = [this, id](const SmtpMessage& /*msg*/, std::string_view error) {
            if (awaiting(id))
                do_fail(id, std::string(error));
        };

        info.smtp_client->send_mail();
    });
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
        url = fmt::format(kFcmUrlTemplate, profile);

    std::vector<std::pair<std::string, std::string>> headers = {
        {"Authorization", prof.auth + " " + prof.token},
        {"Content-Type",  prof.content_type}
    };

    do_send(id, [this, id, url, content, headers] {
        auto mi = messages_.find(id);
        if (mi == messages_.end() || !fetch_)
            return;
        mi->second.phase = Phase::delivering;

        fetch_->post(url, content, headers,
            [this, id](FetchResponse resp) {
                if (!awaiting(id))
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
                if (awaiting(id))
                    do_fail(id, std::string(error));
            });
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

    std::vector<std::pair<std::string, std::string>> headers = {
        {"Content-Type", prof.content_type.empty() ? "application/json" : prof.content_type}
    };

    if (!prof.token.empty())
        headers.push_back({"Authorization",
                           (prof.auth.empty() ? "Bearer" : prof.auth) + " " + prof.token});

    do_send(id, [this, id, url, content, headers] {
        auto mi = messages_.find(id);
        if (mi == messages_.end() || !fetch_)
            return;
        mi->second.phase = Phase::delivering;

        fetch_->post(url, content, headers,
            [this, id](FetchResponse resp) {
                if (!awaiting(id))
                    return;

                if (resp.status_code >= 200 && resp.status_code < 300)
                    do_done(id);
                else
                    do_fail(id, fmt::format("HTTP {}: {}", resp.status_code,
                                            resp.body.substr(0, 256)));
            },
            [this, id](std::string_view error) {
                if (awaiting(id))
                    do_fail(id, std::string(error));
            });
    });
}

// --- do_send -----------------------------------------------------------------
//
// Transition message state: prepared -> sending
//

void MessageServer::do_send(const std::string& id, std::function<void()> deliver)
{
    if (!bot_)
        return;

#ifdef MESSAGESERVER_NOTIFY
    // Path single: nothing leaves before `send` is committed, and `send` is
    // committed only under the row's current token (the hold first). A copy
    // that takes the row over later then finds `prepared` only for a message
    // that never went out, and `sending` for one that may have. A `send` not
    // committed sent nothing: the row is given back (`unsent:`) — or, its
    // token not current (NT409), it is another sender's and is left to it.
    if (single(id)) {
        const auto row = *messages_.at(id).row;
        // quiet: the statement carries a session code (see do_fetch).
        pool_->execute(held(row, outcome_sql(id, "send", {})),
            [this, id, token = row.token, deliver = std::move(deliver)](std::vector<PgResult> results) {
                const auto bad = std::find_if(results.begin(), results.end(),
                    [](const PgResult& r) { return !r.ok(); });

                auto mi = messages_.find(id);
                if (mi == messages_.end() || !mi->second.row)
                    return;

                if (bad == results.end()) {
                    if (mi->second.row->token == token && mi->second.phase == Phase::sending)
                        deliver();
                    return;
                }

                if (std::string_view(bad->sqlstate()) == "NT409" && mi->second.row->token == token) {
                    logger_->warn("MessageServer: message {}: the row is not this delivery's any more — "
                                  "not sent", id);
                    delete_message(id);
                    return;
                }

                logger_->error("MessageServer: message {}: `send` not committed — given back, unsent: {}",
                               id, bad->error_message());
                give_back(id, "unsent: send was not committed");
            },
            {}, /*quiet=*/true, PgRetry::if_lost);
        return;
    }
#endif

    // Sent again after a lost connection (T627), here and in do_done/do_fail:
    // `send` exists only in `prepared`, `done` and `fail` only in `prepared`
    // and `sending`, so a repeat of one that committed is refused by the
    // workflow and lands where `never` would have — the error handler.
    bot_->execute_action(message_session(id), id, "send",
        [](std::vector<PgResult> /*results*/) {},
        [this, id](std::string_view error) {
            logger_->error("MessageServer: do_send failed for {}: {}", id, error);
            if (in_progress(id))
                do_fail(id, "Failed to transition to sending state: " + std::string(error));
        },
        PgRetry::if_lost);

    deliver();
}

// --- do_done -----------------------------------------------------------------
//
// Message sent successfully: done + optional label (external message id).
//

void MessageServer::do_done(const std::string& id, const std::string& msg_id)
{
    logger_->debug("MessageServer: message {} sent successfully", id);

#ifdef MESSAGESERVER_NOTIFY
    if (single(id)) {
        settle_single(id, outcome_sql(id, "done", msg_id));
        return;
    }
#endif

    if (!bot_ || !bot_->valid()) {
        delete_message(id);
        return;
    }

    if (msg_id.empty()) {
        bot_->execute_action(message_session(id), id, "done",
            [this, id](std::vector<PgResult> /*results*/) {
                delete_message(id);
            },
            [this, id](std::string_view err) {
                logger_->error("MessageServer: do_done SQL error for {}: {}", id, err);
                delete_message(id);
            },
            PgRetry::if_lost);
    } else {
        auto sql = fmt::format(
            "SELECT * FROM api.authorize({});\n"
            "SELECT * FROM api.set_object_label({}::uuid, {});\n"
            "SELECT * FROM api.execute_object_action({}::uuid, {})",
            pq_quote_literal(bot_->session()),
            pq_quote_literal(id), pq_quote_literal(msg_id),
            pq_quote_literal(id), pq_quote_literal("done"));

        // quiet: the statement carries a session code. PgPool prints statement
        // text at debug into postgres.log — inside the container, readable
        // by any process there.
        pool_->execute(sql,
            [this, id](std::vector<PgResult> /*results*/) {
                delete_message(id);
            },
            [this, id](std::string_view err) {
                logger_->error("MessageServer: do_done SQL error for {}: {}", id, err);
                delete_message(id);
            },
        /*quiet=*/true, PgRetry::if_lost);
    }
}

// --- do_fail -----------------------------------------------------------------

void MessageServer::do_fail(const std::string& id, const std::string& error)
{
    logger_->error("MessageServer: message {} failed: {}", id, error);

#ifdef MESSAGESERVER_NOTIFY
    if (single(id)) {
        settle_single(id, outcome_sql(id, "fail", error));
        return;
    }
#endif

    if (!bot_ || !bot_->valid()) {
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

    // quiet: the statement carries a session code. PgPool prints statement
    // text at debug into postgres.log — inside the container, readable
    // by any process there.
    pool_->execute(sql,
        [this, id](std::vector<PgResult> /*results*/) {
            delete_message(id);
        },
        [this, id](std::string_view err) {
            logger_->error("MessageServer: do_fail SQL error for {}: {}", id, err);
            delete_message(id);
        },
        /*quiet=*/true, PgRetry::if_lost);
}

// --- delete_message / in_progress / under_limit ------------------------------

std::string MessageServer::message_session(const std::string& id) const
{
    auto it = messages_.find(id);
    if (it != messages_.end() && !it->second.session.empty())
        return it->second.session;
    return bot_ ? bot_->session() : std::string();
}

void MessageServer::delete_message(const std::string& id)
{
    messages_.erase(id);
}

void MessageServer::drop_message(const std::string& id)
{
#ifdef MESSAGESERVER_NOTIFY
    if (single(id)) {
        settle_single(id, {});
        return;
    }
#endif
    delete_message(id);
}

bool MessageServer::in_progress(const std::string& id) const
{
    return messages_.count(id) > 0;
}

bool MessageServer::awaiting(const std::string& id) const
{
    auto it = messages_.find(id);
    return it != messages_.end() && it->second.phase != Phase::settling;
}

bool MessageServer::under_limit() const
{
    return messages_.size() < max_in_flight_;
}

#ifdef MESSAGESERVER_NOTIFY

// --- path single: the mode ---------------------------------------------------
//
// A database without the notify module (an older db-platform) has the path
// legacy only; it is asked again now and then. With the module the mode of
// `outbox` is read until it is single; from then on the subscriber stays for
// the life of the process — a channel returned to legacy still has rows to
// bring to their end, and notify.send alone decides which path a new message
// takes (the LISTEN on "outbox" serves the other one meanwhile).

void MessageServer::probe_notify()
{
    probing_ = true;

    pool_->execute(
        "SELECT to_regprocedure('notify.channel_policy(text)') IS NOT NULL"
        " AND to_regprocedure('notify.take(bigint,integer)') IS NOT NULL",
        [this](std::vector<PgResult> results) {
            probing_ = false;
            next_probe_ = std::chrono::steady_clock::now() + probe_every;
            if (results.empty() || !results[0].ok())
                return;   // not answered: asked again, the poll waits

            const bool yes = results[0].rows() > 0 &&
                             results[0].value(0, 0) != nullptr && results[0].value(0, 0)[0] == 't';
            if (yes && !notify_possible_)
                logger_->notice("MessageServer: the database has the notify module — the channel outbox is "
                                "taken from notify.queue when it is single");
            notify_possible_ = yes;
            probed_ = true;
        },
        [this](std::string_view error) {
            probing_ = false;
            next_probe_ = std::chrono::steady_clock::now() + probe_every;
            logger_->error("MessageServer: the notify module is not probed: {}", error);
        });
}

// The lease of the channel must outlast a delivery: the outcome is written
// lease_margin before it runs out (single_timeout), and a lease no longer
// than that leaves no time for a delivery at all. Short of it the path is not
// taken up — said as an error once per lease value.
void MessageServer::read_mode()
{
    reading_mode_ = true;
    next_mode_ = std::chrono::steady_clock::now() + mode_every;

    pool_->execute(
        "SELECT mode, extract(epoch FROM lease)::bigint FROM notify.channel_policy('outbox')",
        [this](std::vector<PgResult> results) {
            reading_mode_ = false;

            if (notify_ || stopping_)
                return;

            // No row: no channel outbox — nothing but the path legacy.
            if (results.empty() || !results[0].ok() || results[0].rows() == 0 || results[0].columns() < 2)
                return;

            const char* mode = results[0].value(0, 0);
            if (mode == nullptr || std::string_view(mode) != "single")
                return;

            const char* lease = results[0].value(0, 1);
            const long lease_s = lease != nullptr ? std::strtol(lease, nullptr, 10) : 0;

            if (lease_s <= lease_margin.count()) {
                if (lease_s != refused_lease_)
                    logger_->error("MessageServer: the channel outbox is single, its path is not taken up: lease "
                                   "{} s leaves no time for a delivery (the outcome is written {} s before it ends)",
                                   lease_s, lease_margin.count());
                refused_lease_ = lease_s;
                return;
            }

            lease_ = std::chrono::seconds(lease_s);
            start_notify();
        },
        [this](std::string_view error) {
            reading_mode_ = false;
            logger_->error("MessageServer: the mode of the channel outbox is not read: {}", error);
        });
}

void MessageServer::start_notify()
{
    db_platform::NotifySubscriber::Options options;
    options.channel     = "outbox";
    options.node        = node_;
    options.application = "MessageServer";
    options.role        = "message-server";

    notify_ = std::make_unique<db_platform::NotifySubscriber>(*pool_, *loop_, *logger_, std::move(options),
        [this](const db_platform::NotifyRow& row) { on_row(row); });

    logger_->notice("MessageServer: the channel outbox is single — messages are taken from notify.queue "
                    "(lease {} s, an outcome is written within {} ms)", lease_.count(), single_timeout().count());
    notify_->start();
}

// --- path single: a row ------------------------------------------------------

void MessageServer::on_row(const db_platform::NotifyRow& row)
{
    if (stopping_) {
        notify_->refuse(row, "unsent: stopping, taken after the stop began");
        return;
    }

    // The payload is the message id (db.ft_notification_after_insert).
    const std::string& id = row.payload;
    if (id.empty()) {
        logger_->error("MessageServer: row {} of outbox carries no message id — confirmed, nothing to send", row.id);
        notify_->complete(row, {});
        return;
    }

    auto mi = messages_.find(id);
    if (mi != messages_.end()) {
        if (mi->second.row) {
            // Handed out again while still here: the token of the old delivery
            // is not current, the outcome goes out under the new one.
            logger_->warn("MessageServer: message {} delivered again (attempt {}) while still here — "
                          "its outcome goes out under the new delivery", id, row.attempts);
            mi->second.row = row;
        } else {
            // On the path legacy here (a switch in progress): that one writes the outcome.
            logger_->notice("MessageServer: message {} came by notify.queue while sent on the path legacy — "
                            "confirmed, sent once", id);
            notify_->complete(row, {});
        }
        return;
    }

    for (auto& w : waiting_) {
        if (w.row.payload == id) {
            w.row   = row;     // a new delivery: its lease counts from now
            w.taken = std::chrono::steady_clock::now();
            return;
        }
    }

    waiting_.push_back(Waiting{row, std::chrono::steady_clock::now()});
    start_waiting();
}

// Rows wait here while max_in_flight messages are out. One that waited half
// its lease is given back, unsent — another copy may have room; and a row is
// not started without a bot session to act with.
void MessageServer::start_waiting()
{
    if (!notify_ || stopping_)
        return;

    const auto now = std::chrono::steady_clock::now();
    for (auto it = waiting_.begin(); it != waiting_.end(); ) {
        if (lease_.count() > 0 && now - it->taken > lease_ / 2) {
            logger_->warn("MessageServer: message {} waited here past half the lease — given back, unsent",
                          it->row.payload);
            notify_->refuse(it->row, "unsent: waited for a free slot past half the lease");
            it = waiting_.erase(it);
        } else {
            ++it;
        }
    }

    if (!bot_ || !bot_->valid() || bot_->sessions().empty())
        return;

    while (!waiting_.empty() && under_limit()) {
        auto w = std::move(waiting_.front());
        waiting_.pop_front();
        read_single(w.row, w.taken);
    }
}

// The row carries no scope: every scope is asked, as on the path legacy, and
// the one that finds the message acts on it. Nobody finding it — confirmed,
// nothing to send; a read that failed with nobody finding it — given back.
void MessageServer::read_single(const db_platform::NotifyRow& row, std::chrono::steady_clock::time_point taken)
{
    const std::string id = row.payload;
    const auto& sessions = bot_->sessions();

    // The lease runs from the take, not from here: the time the row waited
    // for a slot is counted in the deadline of its outcome (single_timeout).
    const auto waited = std::chrono::steady_clock::now() - taken;

    auto& info      = messages_[id];
    info            = MessageInfo{};
    info.id         = id;
    info.started_at = std::chrono::system_clock::now() -
                      std::chrono::duration_cast<std::chrono::system_clock::duration>(waited);
    info.phase      = Phase::reading;
    info.row        = row;
    info.asks       = sessions.size();

    for (const auto& session : sessions) {
        auto sql = fmt::format(
            "SELECT * FROM api.authorize({});\n"
            "SELECT * FROM api.get_service_message({}::uuid)",
            pq_quote_literal(session),
            pq_quote_literal(id));

        auto answered = [this, id](bool failed) -> MessageInfo* {
            auto mi = messages_.find(id);
            if (mi == messages_.end() || !mi->second.row || mi->second.phase != Phase::reading)
                return nullptr;   // found by another scope, given back, or gone
            auto& info = mi->second;
            if (info.asks > 0)
                --info.asks;
            info.read_failed = info.read_failed || failed;
            return &info;
        };

        // quiet: the statement carries a session code (see do_fetch).
        pool_->execute(sql,
            [this, id, session, answered](std::vector<PgResult> results) {
                const bool failed = std::any_of(results.begin(), results.end(),
                    [](const PgResult& r) { return !r.ok(); });
                auto* info = answered(failed);
                if (!info)
                    return;

                if (!failed && results.size() >= 2 && results[1].rows() > 0) {
                    info->session = session;
                    info->phase   = Phase::sending;
                    dispatch_single(id, results[1]);
                    return;
                }

                if (info->asks > 0)
                    return;

                if (info->read_failed) {
                    give_back(id, "unsent: the message could not be read");
                    return;
                }

                logger_->notice("MessageServer: message {} is in no scope of the bot — confirmed, nothing to send", id);
                settle_single(id, {});
            },
            [this, id, answered](std::string_view error) {
                logger_->error("MessageServer: message {} not read: {}", id, error);
                auto* info = answered(true);
                if (info && info->asks == 0)
                    give_back(id, "unsent: the message could not be read");
            },
            /*quiet=*/true);
    }
}

// By the state of the message, not by the delivery count: `prepared` never
// went out (nothing leaves before `send` commits), `sending` may have.
void MessageServer::dispatch_single(const std::string& id, const PgResult& res)
{
    const int col_state = res.column_index("statecode");
    const std::string state = (col_state >= 0 && res.value(0, col_state)) ? res.value(0, col_state) : "";

    if (state == "prepared") {
        dispatch_message(id, res, 0);
        return;
    }

    if (state == "sending") {
        const int attempt = single(id) ? messages_.at(id).row->attempts : 0;
        do_fail(id, fmt::format("outcome unknown: found in 'sending' at delivery {} — an earlier sender may have "
                                "sent it; not sent again", attempt));
        return;
    }

    logger_->notice("MessageServer: message {} is '{}' — confirmed, nothing to send", id, state);
    settle_single(id, {});
}

// --- path single: the outcome ------------------------------------------------
//
// `done` or `fail` (and the label) with the confirmation, in the scope the
// message was found in, as one transaction: under a token that is not current
// the whole of it is rolled back (NT409) — the row is another sender's.

std::string MessageServer::outcome_sql(const std::string& id, std::string_view action,
                                       const std::string& label) const
{
    const auto quoted = pq_quote_literal(id);
    std::string sql = fmt::format("SELECT * FROM api.authorize({});\n", pq_quote_literal(message_session(id)));
    if (!label.empty())
        sql += fmt::format("SELECT * FROM api.set_object_label({}::uuid, {});\n", quoted, pq_quote_literal(label));
    sql += fmt::format("SELECT * FROM api.execute_object_action({}::uuid, {})", quoted,
                       pq_quote_literal(std::string(action)));
    return sql;
}

// The first send goes through the subscriber, which takes the row off its
// list. A failure there may be a lost connection or a statement that failed:
// the same statement is sent once more by the module itself, on a pool that
// resends after a lost connection — committed the first time, it is refused
// by the hold (NT409) and changes nothing.
void MessageServer::settle_single(const std::string& id, std::string sql)
{
    auto mi = messages_.find(id);
    if (mi == messages_.end() || !mi->second.row)
        return;

    auto& info = mi->second;
    info.phase = Phase::settling;
    const auto row = *info.row;

    if (!notify_) {
        settle_again(id, row, std::move(sql));
        return;
    }

    auto on_done = [this, id, token = row.token](std::vector<PgResult>) {
        auto it = messages_.find(id);
        if (it != messages_.end() && it->second.row && it->second.row->token == token)
            delete_message(id);
    };
    auto on_fail = [this, id, row, sql](std::string_view error, bool stale) {
        if (stale) {
            settle_stale(id, row, sql);
            return;
        }
        logger_->warn("MessageServer: message {}: outcome and confirmation not written ({}) — sent again", id, error);
        settle_again(id, row, sql);
    };

    // quiet: the statement carries a session code (see do_fetch).
    notify_->complete(row, held(row, sql), std::move(on_done), std::move(on_fail), /*quiet=*/true);
}

void MessageServer::settle_again(const std::string& id, const db_platform::NotifyRow& row, std::string sql)
{
    auto statement = db_platform::NotifySubscriber::ack_sql(row, held(row, sql));

    pool_->execute(std::move(statement),
        [this, id, row, sql](std::vector<PgResult> results) {
            const auto bad = std::find_if(results.begin(), results.end(),
                [](const PgResult& r) { return !r.ok(); });

            auto it = messages_.find(id);
            const bool mine = it != messages_.end() && it->second.row && it->second.row->token == row.token;

            if (bad == results.end()) {
                if (mine)
                    delete_message(id);
                return;
            }

            if (std::string_view(bad->sqlstate()) == "NT409" || !mine) {
                settle_stale(id, row, sql);
                return;
            }

            logger_->error("MessageServer: message {}: outcome not written, its row returns by the lease: {}",
                           id, bad->error_message());
            delete_message(id);
        },
        {}, /*quiet=*/true, PgRetry::if_lost);
}

// NT409: what was sent with the confirmation is rolled back. Either an earlier
// send of this very outcome committed (a resend after a lost connection), or
// the row went to another sender — or, delivered again meanwhile, it is this
// module's under a new token.
void MessageServer::settle_stale(const std::string& id, const db_platform::NotifyRow& row, std::string sql)
{
    auto it = messages_.find(id);
    if (it == messages_.end() || !it->second.row)
        return;

    if (it->second.row->token != row.token) {
        logger_->notice("MessageServer: message {}: delivered again meanwhile — the outcome goes out under the new "
                        "delivery", id);
        settle_single(id, std::move(sql));
        return;
    }

    logger_->warn("MessageServer: message {}: the row is not this delivery's any more — the outcome written here "
                  "is rolled back (written already, or by the sender that holds the row now)", id);
    delete_message(id);
}

// Read but not handed to a transport: back to the queue for another copy.
void MessageServer::give_back(const std::string& id, std::string_view reason)
{
    auto mi = messages_.find(id);
    if (mi == messages_.end() || !mi->second.row)
        return;

    const auto row = *mi->second.row;
    delete_message(id);
    if (notify_)
        notify_->refuse(row, reason);
}

// --- path single: the stop ---------------------------------------------------
//
// NotifySubscriber::stop() is not called: it gives back every row still with
// the module, the ones out with a transport too, and the next copy would send
// them again beside the delivery (or after it). Here a row out with a
// transport stays taken and returns by its lease; one not started is given
// back; the subscriber is deregistered — in one batch on the listener, as the
// subscriber does it (the pool's connections may be held by work that hangs).

void MessageServer::stop_notify()
{
    if (!notify_)
        return;

    const int number = notify_->number();

    std::string sql;
    if (number != 0)
        sql += fmt::format("SELECT notify.drain({}); ", number);

    auto nack = [&sql](const db_platform::NotifyRow& row, std::string_view reason) {
        sql += fmt::format(
            "DO $outbox$ BEGIN PERFORM notify.nack({}, {}, {}); "
            "EXCEPTION WHEN SQLSTATE 'NT409' THEN NULL; END $outbox$; ",
            row.id, row.token, pq_quote_literal(std::string(reason)));
    };

    std::size_t refused = 0;
    for (const auto& w : waiting_) {
        nack(w.row, "unsent: stopping, not started");
        ++refused;
    }
    waiting_.clear();

    std::vector<std::string> unread;
    std::size_t left = 0;
    for (const auto& [id, info] : messages_) {
        if (!info.row)
            continue;
        if (info.phase == Phase::reading) {
            nack(*info.row, "unsent: stopping, not sent yet");
            unread.push_back(id);
            ++refused;
        } else if (info.phase != Phase::settling) {
            ++left;
        }
    }
    for (const auto& id : unread)
        delete_message(id);

    if (number != 0)
        sql += fmt::format("SELECT notify.unsubscribe({})", number);

    if (left > 0)
        logger_->warn("MessageServer: stopping with {} message(s) out with a transport — not failed: each row "
                      "returns by its lease", left);

    if (!sql.empty()) {
        logger_->notice("MessageServer: subscriber {} of outbox stopping — {} unsent row(s) given back, "
                        "deregistering", number, refused);
        try {
            pool_->listener_execute(std::move(sql),
                [this](std::vector<PgResult> results) {
                    const auto bad = std::find_if(results.begin(), results.end(),
                        [](const PgResult& r) { return !r.ok(); });
                    if (bad != results.end())
                        logger_->error("MessageServer: the subscriber of outbox did not stop cleanly: {}",
                                       bad->error_message());
                },
                {}, /*quiet=*/false);
        } catch (const std::exception& e) {
            // The rows return by their lease, the subscriber is forgotten by
            // its heartbeat: nothing here outlives the process.
            logger_->error("MessageServer: the subscriber of outbox not deregistered, the pool refused: {}", e.what());
        }
    }

    notify_.reset();
}

bool MessageServer::single(const std::string& id) const
{
    auto it = messages_.find(id);
    return it != messages_.end() && it->second.row.has_value();
}

std::chrono::milliseconds MessageServer::single_timeout() const
{
    if (lease_ <= lease_margin)
        return message_timeout_;
    return std::min(message_timeout_, std::chrono::duration_cast<milliseconds>(lease_ - lease_margin));
}

#endif // MESSAGESERVER_NOTIFY

// --- on_fatal ----------------------------------------------------------------

void MessageServer::on_fatal(const std::string& error)
{
    status_ = Status::stopped;
    next_check_ = std::chrono::system_clock::now() + std::chrono::seconds(10);
    logger_->error("MessageServer: fatal error, pausing 10s: {}", error);
}

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
