/*++

Program name:

  Apostol Web Service

Module Name:

  MessageServer.cpp

Notices:

  Process: Mail Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#include "Core.hpp"
#include "MessageServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

#define SYSTEM_PROVIDER_NAME "system"
#define SERVICE_APPLICATION_NAME "service"

#define GOOGLE_PROVIDER_NAME "google"
#define FIREBASE_APPLICATION_NAME "firebase"

#define CONFIG_SECTION_NAME "process/MessageServer"

#define API_BOT_USERNAME "apibot"
#define MAIL_BOT_USERNAME "mailbot"

#define QUERY_INDEX_MESSAGE 1

extern "C++" {

namespace Apostol {

    namespace Processes {

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageServer --------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CMessageServer::CMessageServer(CCustomProcess *AParent, CApplication *AApplication):
                inherited(AParent, AApplication, "message server") {

            m_Agent = CString().Format("Message Server (%s)", Application()->Title().c_str());
            m_Host = CApostolModule::GetIPByHostName(CApostolModule::GetHostName());

            m_AuthDate = 0;
            m_FixedDate = 0;
            m_CheckDate = 0;

            m_Status = psStopped;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::BeforeRun() {
            sigset_t set;

            Application()->Header(Application()->Name() + ": message server");

            Log()->Debug(APP_LOG_DEBUG_CORE, MSG_PROCESS_START, GetProcessName(), Application()->Header().c_str());

            InitSignals();

            Reload();

            SetUser(Config()->User(), Config()->Group());

            InitializePQServer(Application()->Title());

            PQServerStart(_T("helper"));

            SigProcMask(SIG_UNBLOCK, SigAddSet(&set));

            SetTimerInterval(1000);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::AfterRun() {
            CApplicationProcess::AfterRun();
            PQServerStop();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Run() {
            while (!sig_exiting) {

                Log()->Debug(APP_LOG_DEBUG_EVENT, _T("message server cycle"));

                try
                {
                    PQServer().Wait();
                }
                catch (Delphi::Exception::Exception &E)
                {
                    Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
                }

                if (sig_terminate || sig_quit) {
                    if (sig_quit) {
                        sig_quit = 0;
                        Log()->Debug(APP_LOG_DEBUG_EVENT, _T("gracefully shutting down"));
                        Application()->Header(_T("message server is shutting down"));
                    }

                    //DoExit();

                    if (!sig_exiting) {
                        sig_exiting = 1;
                    }
                }

                if (sig_reconfigure) {
                    sig_reconfigure = 0;
                    Log()->Debug(APP_LOG_DEBUG_EVENT, _T("reconfiguring"));

                    Reload();
                }

                if (sig_reopen) {
                    sig_reopen = 0;
                    Log()->Debug(APP_LOG_DEBUG_EVENT, _T("reopening logs"));
                }
            }

            Log()->Debug(APP_LOG_DEBUG_EVENT, _T("stop message server"));
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CMessageServer::CreateToken(const CProvider& Provider, const CString &Application) {
            auto token = jwt::create()
                    .set_issuer(Provider.Issuer(Application))
                    .set_audience(Provider.ClientId(Application))
                    .set_issued_at(std::chrono::system_clock::now())
                    .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
                    .sign(jwt::algorithm::hs256{std::string(Provider.Secret(Application))});

            return token;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CMessageServer::CreateGoogleToken(const CProvider &Provider, const CString &Application) {

            const auto& private_key = std::string(Provider.Applications()[Application]["private_key"].AsString());

            const auto& kid = std::string(Provider.Applications()[Application]["private_key_id"].AsString());
            const auto& public_key = std::string(Provider.PublicKey(kid));

            const auto& iss = std::string(Provider.Applications()[Application]["client_email"].AsString());
            const auto& aud = std::string("https://oauth2.googleapis.com/token");
            const auto& scope = std::string("https://www.googleapis.com/auth/firebase.messaging");

            auto token = jwt::create()
                    .set_issuer(iss)
                    .set_audience(aud)
                    .set_payload_claim("scope", jwt::claim(scope))
                    .set_issued_at(std::chrono::system_clock::now())
                    .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
                    .sign(jwt::algorithm::rs256{public_key, private_key});

            return token;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CreateAccessToken(const CProvider &Provider, const CString &Application, CStringList &Tokens) {

            auto OnDone = [&Tokens](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                const CJSON Json(pReply->Content);

                Tokens.Values("access_token", Json["access_token"].AsString());

                return true;
            };

            CString server_uri("http://localhost:");
            server_uri << (int) Config()->Port();

            const auto &token_uri = Provider.TokenURI(Application);
            const auto &service_token = Application == FIREBASE_APPLICATION_NAME ? CreateGoogleToken(Provider, Application) : CreateToken(Provider, Application);

            Tokens.Values("service_token", service_token);

            if (!token_uri.IsEmpty()) {
                FetchAccessToken(token_uri.front() == '/' ? server_uri + token_uri : token_uri, service_token, OnDone);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::FetchCerts(CProvider &Provider, const CString &Application) {

            const auto& URI = Provider.CertURI(Application);

            if (URI.IsEmpty()) {
                Log()->Error(APP_LOG_INFO, 0, _T("Certificate URI in provider \"%s\" is empty."), Provider.Name().c_str());
                return;
            }

            Log()->Error(APP_LOG_INFO, 0, _T("Trying to fetch public keys from: %s"), URI.c_str());

            auto OnRequest = [&Provider, &Application](CHTTPClient *Sender, CHTTPRequest *ARequest) {
                const auto& client_x509_cert_url = std::string(Provider.Applications()[Application]["client_x509_cert_url"].AsString());

                Provider.KeyStatusTime(Now());
                Provider.KeyStatus(ksFetching);

                CLocation Location(client_x509_cert_url);
                CHTTPRequest::Prepare(ARequest, "GET", Location.pathname.c_str());
            };

            auto OnExecute = [this, &Provider, &Application](CTCPConnection *AConnection) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pReply = pConnection->Reply();

                try {
                    DebugRequest(pConnection->Request());
                    DebugReply(pReply);

                    Provider.KeyStatusTime(Now());

                    Provider.Keys().Clear();
                    Provider.Keys() << pReply->Content;

                    Provider.KeyStatus(ksSuccess);

                    CreateAccessToken(Provider, Application, m_Tokens[Provider.Name()]);
                } catch (Delphi::Exception::Exception &E) {
                    Provider.KeyStatus(ksFailed);
                    Log()->Error(APP_LOG_ERR, 0, "[Certificate] Message: %s", E.what());
                }

                pConnection->CloseConnection(true);
                return true;
            };

            auto OnException = [&Provider](CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                Provider.KeyStatusTime(Now());
                Provider.KeyStatus(ksFailed);

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            CLocation Location(URI);
            auto pClient = GetClient(Location.hostname, Location.port);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(OnExecute);
            pClient->OnException(OnException);

            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::FetchProviders() {
            for (int i = 0; i < m_Providers.Count(); i++) {
                auto& Provider = m_Providers[i].Value();
                for (int j = 0; j < Provider.Applications().Count(); ++j) {
                    const auto &app = Provider.Applications().Members(j);
                    if (app["type"].AsString() == "service_account") {
                        if (!app["auth_provider_x509_cert_url"].AsString().IsEmpty()) {
                            if (Provider.KeyStatus() == ksUnknown) {
                                FetchCerts(Provider, app.String());
                            }
                        } else {
                            if (Provider.KeyStatus() == ksUnknown) {
                                Provider.KeyStatusTime(Now());
                                CreateAccessToken(Provider, app.String(), m_Tokens[Provider.Name()]);
                                Provider.KeyStatus(ksSuccess);
                            }
                        }
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckProviders() {
            for (int i = 0; i < m_Providers.Count(); i++) {
                auto& Provider = m_Providers[i].Value();
                if (Provider.KeyStatus() != ksUnknown) {
                    Provider.KeyStatusTime(Now());
                    Provider.KeyStatus(ksUnknown);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CMessageServer::InProgress(const CString &MsgId) {
            for (int i = 0; i < m_ClientManager.Count(); ++i) {
                auto pClient = m_ClientManager[i];
                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    if (pMessage->MsgId() == MsgId)
                        return true;
                }
            }
            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::LoadSMTPConfig(const CString &FileName, CSMTPConfigs &Configs) {

            const CString Prefix(Config()->Prefix());
            CString configFile(FileName);

            if (!path_separator(configFile.front())) {
                configFile = Prefix + configFile;
            }

            if (FileExists(configFile.c_str())) {
                CIniFile IniFile(configFile.c_str());
                IniFile.OnIniFileParseError(OnIniFileParseError);

                CStringList Sections;
                IniFile.ReadSections(&Sections);

                for (int i = 0; i < Sections.Count(); i++) {
                    const auto& Section = Sections[i];
                    int Index = Configs.AddPair(Section, CSMTPConfig());
                    auto& Config = Configs[Index].Value();
                    InitSMTPConfig(IniFile, Section, Config);
                }

                auto& defaultConfig = Configs.Default();
                if (defaultConfig.Name().IsEmpty()) {
                    defaultConfig.Name() = _T("default");
                    auto& Config = defaultConfig.Value();
                    InitSMTPConfig(IniFile, defaultConfig.Name(), Config);
                }
            } else {
                Log()->Error(APP_LOG_WARN, 0, APP_FILE_NOT_FOUND, configFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitSMTPConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config) {
            Config.Location() = IniFile.ReadString(Section, "host", "http://localhost:25");
            Config.UserName() = IniFile.ReadString(Section, "username", "smtp");
            Config.Password() = IniFile.ReadString(Section, "password", "smtp");
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config) {
            IniFile.ReadSectionValues(Profile.c_str(), &Config);
        }
        //--------------------------------------------------------------------------------------------------------------

        CSMTPClient *CMessageServer::GetSMTPClient(const CSMTPConfig &Config) {

            auto pClient = m_MailManager.Add(Config);

            pClient->PollStack(PQServer().PollStack());

            pClient->ClientName() = Application()->Title();

            pClient->AutoConnect(true);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pClient->OnVerbose([this](auto && Sender, auto && AConnection, auto && AFormat, auto && args) { DoVerbose(Sender, AConnection, AFormat, args); });
            pClient->OnAccessLog([this](auto && AConnection) { DoAccessLog(AConnection); });
            pClient->OnException([this](auto && AConnection, auto && AException) { DoException(AConnection, AException); });
            pClient->OnEventHandlerException([this](auto && AHandler, auto && AException) { DoServerEventHandlerException(AHandler, AException); });
            pClient->OnConnected([this](auto && Sender) { DoSMTPConnected(Sender); });
            pClient->OnDisconnected([this](auto && Sender) { DoSMTPDisconnected(Sender); });
            pClient->OnNoCommandHandler([this](auto && Sender, auto && AData, auto && AConnection) { DoNoCommandHandler(Sender, AData, AConnection); });

            pClient->OnRequest([this](auto && Sender) { DoSMTPRequest(Sender); });
            pClient->OnReply([this](auto && Sender) { DoSMTPReply(Sender); });
#else
            pClient->OnVerbose(std::bind(&CMessageServer::DoVerbose, this, _1, _2, _3, _4));
            pClient->OnAccessLog(std::bind(&CMessageServer::DoAccessLog, this, _1));
            pClient->OnException(std::bind(&CMessageServer::DoException, this, _1, _2));
            pClient->OnEventHandlerException(std::bind(&CMessageServer::DoServerEventHandlerException, this, _1, _2));
            pClient->OnConnected(std::bind(&CMessageServer::DoSMTPConnected, this, _1));
            pClient->OnDisconnected(std::bind(&CMessageServer::DoSMTPDisconnected, this, _1));
            pClient->OnNoCommandHandler(std::bind(&CMessageServer::DoNoCommandHandler, this, _1, _2, _3));

            pClient->OnRequest(std::bind(&CMessageServer::DoSMTPRequest, this, _1));
            pClient->OnReply(std::bind(&CMessageServer::DoSMTPReply, this, _1));
#endif

            return pClient;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Reload() {
            CServerProcess::Reload();

            m_Configs.Clear();
            m_Providers.Clear();
            m_Profiles.Clear();

            CStringList configs;
            Config()->IniFile().ReadSection(CONFIG_SECTION_NAME, &configs);

            for (int i = 0; i < configs.Count(); ++i) {
                const auto& config = configs[i].Lower();

                if (config == "enable")
                    continue;

                if (config == "smtp") {
                    LoadSMTPConfig(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, config, CString().Format("conf/%s.conf", config.c_str())), m_Configs);
                } else {
                    m_Profiles.AddPair(config, CStringListPairs());
                    LoadConfig(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, config, CString().Format("conf/%s.conf", config.c_str())), m_Profiles[config], InitConfig);
                }
            }

            for (int i = 0; i < m_Profiles.Count(); ++i) {
                const auto &profile = m_Profiles[i].Value();
                for (int j = 0; j < profile.Count(); ++j) {
                    const auto &config = profile[j].Value();
                    const auto &oauth2 = config["oauth2"];
                    if (!oauth2.IsEmpty()) {
                        const auto &provider = config["provider"];
                        const auto &application = config["application"];
                        m_Tokens.AddPair(provider, CStringList());
                        LoadOAuth2(oauth2, provider.empty() ? SYSTEM_PROVIDER_NAME : provider, application.empty() ? SERVICE_APPLICATION_NAME : application, m_Providers);
                    }
                }
            }

            m_AuthDate = 0;
            m_FixedDate = 0;
            m_CheckDate = 0;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CMessageServer::DoExecute(CTCPConnection *AConnection) {
            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitListen() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {
                try {
                    auto pResult = APollQuery->Results(0);

                    if (pResult->ExecStatus() != PGRES_COMMAND_OK) {
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());
                    }

                    APollQuery->Connection()->Listener(true);
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    APollQuery->Connection()->OnNotify([this](auto && APollQuery, auto && ANotify) { DoPostgresNotify(APollQuery, ANotify); });
#else
                    APollQuery->Connection()->OnNotify(std::bind(&CMessageServer::DoPostgresNotify, this, _1, _2));
#endif
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            CStringList SQL;

            SQL.Add("LISTEN outbox;");

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckListen() {
            int Index = 0;
            while (Index < PQServer().PollManager()->Count() && !PQServer().Connections(Index)->Listener())
                Index++;

            if (Index == PQServer().PollManager()->Count())
                InitListen();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Authentication() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);

                    m_Session = pqResults[0][0]["session"];
                    m_Secret = pqResults[0][0]["secret"];

                    m_ApiBot = pqResults[1][0]["get_session"];
                    m_MailBot = pqResults[2][0]["get_session"];

                    m_AuthDate = Now() + (CDateTime) 24 / HoursPerDay;

                    m_Status = psRunning;
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            CString Application(SERVICE_APPLICATION_NAME);

            const auto &Providers = Server().Providers();
            const auto &Provider = Providers.DefaultValue();

            m_ClientId = Provider.ClientId(Application);
            m_ClientSecret = Provider.Secret(Application);

            CStringList SQL;

            api::login(SQL, m_ClientId, m_ClientSecret, m_Agent, m_Host);
            api::get_session(SQL, API_BOT_USERNAME, m_Agent, m_Host);
            api::get_session(SQL, MAIL_BOT_USERNAME, m_Agent, m_Host);

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendSMTP(const CStringPairs &Record) {

            const auto &id = Record.Values("id");
            const auto &profile = Record.Values("profile");

            const auto pos = profile.Find('@');
            const auto &config = pos == CString::npos ? profile : profile.SubString(0, pos);

            const auto &from = m_Configs[config].UserName();
            const auto &address = Record.Values("address");
            const auto &subject = Record.Values("subject");
            const auto &content = Record.Values("content");

            auto pSMTPClient = GetSMTPClient(m_Configs[config]);

            auto &Message = pSMTPClient->NewMessage();

            Message.MessageId() = id;
            Message.From() = from;
            Message.To() = address;
            Message.Subject() = subject;
            Message.Body() = content;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            Message.OnDone([this](auto &&Message) { DoDone(Message); });
            Message.OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
            Message.OnDone(std::bind(&CMessageServer::DoDone, this, _1));
                    Message.OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
            pSMTPClient->SendMail();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendAPI(const CStringPairs &Record, const CStringListPairs &Config) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &auth = Sender->Data()["auth"];
                const auto &token = Sender->Data()["token"];
                const auto &content_type = Sender->Data()["content_type"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), content_type.empty() ? _T("application/json") : content_type.c_str());

                if (!token.IsEmpty()) {
                    ARequest->AddHeader(_T("Authorization"), (auth.empty() ? _T("Bearer") : auth) + " " + token);
                }

                DebugRequest(ARequest);
            };

            auto OnExecute = [this](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {

                    const auto& agent = pClient->Data()["agent"];
                    const auto& area = pClient->Data()["area"];

                    CStringList SQL;

                    api::authorize(SQL, m_ApiBot);
                    api::set_session_area(SQL, area);
                    api::add_inbox(SQL, pMessage->MessageId(), agent, CString(), pMessage->From(), pMessage->To().First(), pMessage->Subject(), pReply->Content);

                    try {
                        ExecSQL(SQL);
                        pMessage->Done();
                    } catch (Delphi::Exception::Exception &E) {
                        DoError(E);
                    }
                }

                return true;
            };

            auto OnException = [](CTCPConnection *Sender, const Delphi::Exception::Exception &E) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    pMessage->Fail(E.what());
                }

                DebugReply(pConnection->Reply());

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            const auto &id = Record.Values("id");

            const auto &agent = Record.Values("agent");
            const auto &area = Record.Values("area");

            const auto &profile = Record.Values("profile");
            const auto &address = Record.Values("address");
            const auto &subject = Record.Values("subject");
            const auto &content = Record.Values("content");

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pMessage->OnDone([this](auto &&Message) { DoDone(Message); });
            pMessage->OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
            pMessage->OnDone(std::bind(&CMessageServer::DoDone, this, _1));
            pMessage->OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
            const auto& uri = Config[profile]["uri"];
            const auto& auth = Config[profile]["auth"];
            const auto& token = Config[profile]["token"];
            const auto& provider = Config[profile]["provider"].Lower();
            const auto& token_type = Config[profile]["token_type"].Lower();
            const auto& content_type = Config[profile]["content_type"].Lower();

            CLocation URI(uri + (address.front() == '/' ? address : '/' + address));

            auto pClient = GetClient(URI.hostname, URI.port);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("auth", auth);

            if (token_type == "oauth2") {
                pClient->Data().Values("token", m_Tokens[provider.empty() ? SYSTEM_PROVIDER_NAME : provider]["access_token"]);
            } else {
                pClient->Data().Values("token", token);
            }

            pClient->Data().Values("content_type", content_type);

            pClient->Data().Values("agent", agent);
            pClient->Data().Values("area", area);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(OnExecute);
            pClient->OnException(OnException);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pClient->OnConnected([this](auto &&Sender) { DoAPIConnected(Sender); });
            pClient->OnDisconnected([this](auto &&Sender) { DoAPIDisconnected(Sender); });
#else
            pClient->OnConnected(std::bind(&CMessageServer::DoAPIConnected, this, _1));
                    pClient->OnDisconnected(std::bind(&CMessageServer::DoAPIDisconnected, this, _1));
#endif
            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendFCM(const CStringPairs &Record, const CStringListPairs &Config) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &token = Sender->Data()["token"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/json"));

                ARequest->AddHeader("Authorization", "Bearer " + token);

                DebugRequest(ARequest);
            };

            auto OnExecute = [](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    const CJSON Json(pReply->Content);

                    if (Json.HasOwnProperty("error")) {
                        pMessage->Fail(Json["error"]["message"].AsString());
                    } else {
                        pMessage->MsgId() = Json["name"].AsString();
                        pMessage->Done();
                    }
                }

                return true;
            };

            auto OnException = [](CTCPConnection *Sender, const Delphi::Exception::Exception &E) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    pMessage->Fail(E.what());
                }

                DebugReply(pConnection->Reply());

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            const auto &id = Record.Values("id");
            const auto &profile = Record.Values("profile");
            const auto &address = Record.Values("address");
            const auto &subject = Record.Values("subject");
            const auto &content = Record.Values("content");

            const auto &provider = Config[profile]["provider"].Lower();
            const auto &token = m_Tokens[provider.empty() ? GOOGLE_PROVIDER_NAME : provider]["access_token"];

            if (token.IsEmpty())
                return;

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pMessage->OnDone([this](auto &&Message) { DoDone(Message); });
            pMessage->OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
            pMessage->OnDone(std::bind(&CMessageServer::DoDone, this, _1));
            pMessage->OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
            const auto &uri = Config[profile]["uri"];

            CLocation URI(uri.IsEmpty() ? CString().Format("https://fcm.googleapis.com/v1/projects/%s/messages:send", profile.c_str()) : uri);

            auto pClient = GetClient(URI.hostname, URI.port);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("token", token);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(OnExecute);
            pClient->OnException(OnException);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pClient->OnConnected([this](auto &&Sender) { DoAPIConnected(Sender); });
            pClient->OnDisconnected([this](auto &&Sender) { DoAPIDisconnected(Sender); });
#else
            pClient->OnConnected(std::bind(&CMessageServer::DoAPIConnected, this, _1));
                    pClient->OnDisconnected(std::bind(&CMessageServer::DoAPIDisconnected, this, _1));
#endif
            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendM2M(const CStringPairs &Record, const CStringListPairs &Config) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &token = Sender->Data()["token"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/soap+xml; charset=utf-8"));

                ARequest->AddHeader("Authorization", "Bearer " + token);

                DebugRequest(ARequest);
            };

            auto OnExecute = [this](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {

                    const auto& agent = pClient->Data()["agent"];
                    const auto& area = pClient->Data()["area"];

                    CStringList SQL;

                    api::authorize(SQL, m_ApiBot);
                    api::set_session_area(SQL, area);
                    api::add_inbox(SQL, pMessage->MessageId(), agent, CString(), pMessage->From(), pMessage->To().First(), pMessage->Subject(), pReply->Content);

                    try {
                        ExecSQL(SQL);
                        pMessage->Done();
                    } catch (Delphi::Exception::Exception &E) {
                        DoError(E);
                    }
                }

                return true;
            };

            auto OnException = [](CTCPConnection *Sender, const Delphi::Exception::Exception &E) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    pMessage->Fail(E.what());
                }

                DebugReply(pConnection->Reply());

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            const auto &id = Record.Values("id");

            const auto &agent = Record.Values("agent");
            const auto &area = Record.Values("area");

            const auto &profile = Record.Values("profile");
            const auto &address = Record.Values("address");
            const auto &subject = Record.Values("subject");
            const auto &content = Record.Values("content");

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pMessage->OnDone([this](auto &&Message) { DoDone(Message); });
            pMessage->OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
            pMessage->OnDone(std::bind(&CMessageServer::DoDone, this, _1));
            pMessage->OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
            const auto &host = "https://api.mcommunicator.ru/m2m/m2m_api.asmx";

            const auto &uri = Config[profile]["uri"];
            const auto &token = Config[profile]["apikey"];

            CLocation URI(uri.empty() ? host : uri);

            auto pClient = GetClient(URI.hostname, URI.port);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("token", token);

            pClient->Data().Values("agent", agent);
            pClient->Data().Values("area", area);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(OnExecute);
            pClient->OnException(OnException);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pClient->OnConnected([this](auto &&Sender) { DoAPIConnected(Sender); });
            pClient->OnDisconnected([this](auto &&Sender) { DoAPIDisconnected(Sender); });
#else
            pClient->OnConnected(std::bind(&CMessageServer::DoAPIConnected, this, _1));
                    pClient->OnDisconnected(std::bind(&CMessageServer::DoAPIDisconnected, this, _1));
#endif
            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendSBA(const CStringPairs &Record, const CStringListPairs &Config) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &username = Sender->Data()["username"];
                const auto &password = Sender->Data()["password"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    CStringList DataForm;

                    DataForm.LineBreak("&");
                    DataForm.Delimiter('&');

                    DataForm = pMessage->Content();

                    DataForm.AddPair("userName", username);
                    DataForm.AddPair("password", password);

                    for (int i = 0; i < DataForm.Count(); ++i) {
                        const auto& name = DataForm.Names(i);
                        const auto& value = DataForm.ValueFromIndex(i);
                        DataForm.Values(name, CHTTPServer::URLEncode(value));
                    }

                    ARequest->Content = DataForm.Text();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/x-www-form-urlencoded"));

                DebugRequest(ARequest);
            };

            auto OnExecute = [this](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {

                    const auto& agent = pClient->Data()["agent"];
                    const auto& area = pClient->Data()["area"];

                    CStringList SQL;

                    api::authorize(SQL, m_ApiBot);
                    api::set_session_area(SQL, area);
                    api::add_inbox(SQL, pMessage->MessageId(), agent, CString(), pMessage->From(), pMessage->To().First(), pMessage->Subject(), pReply->Content);

                    try {
                        ExecSQL(SQL);
                        pMessage->Done();
                    } catch (Delphi::Exception::Exception &E) {
                        DoError(E);
                    }
                }

                return true;
            };

            auto OnException = [](CTCPConnection *Sender, const Delphi::Exception::Exception &E) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    pMessage->Fail(E.what());
                }

                DebugReply(pConnection->Reply());

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            const auto &id = Record.Values("id");

            const auto &agent = Record.Values("agent");
            const auto &area = Record.Values("area");

            const auto &profile = Record.Values("profile");
            const auto &address = Record.Values("address");
            const auto &subject = Record.Values("subject");
            const auto &content = Record.Values("content");

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pMessage->OnDone([this](auto &&Message) { DoDone(Message); });
            pMessage->OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
            pMessage->OnDone(std::bind(&CMessageServer::DoDone, this, _1));
            pMessage->OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
            const auto &host = profile == "test" ? "https://3dsec.sberbank.ru" : "https://securepayments.sberbank.ru";

            const auto &uri = Config[profile]["uri"];
            const auto &userName = Config[profile]["username"];
            const auto &password = Config[profile]["password"];

            CLocation URI((uri.empty() ? host : uri) + (address.front() == '/' ? address : '/' + address));

            auto pClient = GetClient(URI.hostname, URI.port);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("username", userName);
            pClient->Data().Values("password", password);

            pClient->Data().Values("agent", agent);
            pClient->Data().Values("area", area);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(OnExecute);
            pClient->OnException(OnException);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pClient->OnConnected([this](auto &&Sender) { DoAPIConnected(Sender); });
            pClient->OnDisconnected([this](auto &&Sender) { DoAPIDisconnected(Sender); });
#else
            pClient->OnConnected(std::bind(&CMessageServer::DoAPIConnected, this, _1));
                    pClient->OnDisconnected(std::bind(&CMessageServer::DoAPIDisconnected, this, _1));
#endif
            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckMessages(const CPQueryResult& Messages) {

            for (int i = 0; i < Messages.Count(); ++i) {

                const auto &Record = Messages[i];

                const auto &type = Record.Values("agenttypecode");
                const auto &agent = Record.Values("agentcode");

                if (type == "email.agent") {
                    if (agent == "smtp.agent") {
                        SendSMTP(Record);
                    }
                } else if (type == "api.agent") {
                    if (agent == "fcm.agent") {
                        SendFCM(Record, m_Profiles["fcm"]);
                    } else if (agent == "m2m.agent") {
                        SendM2M(Record, m_Profiles["m2m"]);
                    } else if (agent == "sba.agent") {
                        SendSBA(Record, m_Profiles["sba"]);
                    } else {
                        SendAPI(Record, m_Profiles["api"]);
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckOutbox() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);
                    CheckMessages(pqResults[QUERY_INDEX_MESSAGE]);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            CStringList SQL;

            api::authorize(SQL, m_MailBot);
            api::outbox(SQL, "prepared");

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoError(const Delphi::Exception::Exception &E) {
            const auto now = Now();

            m_Session.Clear();
            m_Secret.Clear();

            m_AuthDate = 0;
            m_CheckDate = 0;

            m_Status = psStopped;

            Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoHeartbeat() {
            const auto now = Now();

            if ((now >= m_FixedDate)) {
                m_FixedDate = now + (CDateTime) 55 / MinsPerDay; // 55 min
                CheckProviders();
                FetchProviders();
                CheckListen();
            }

            if ((now >= m_AuthDate)) {
                m_AuthDate = now + (CDateTime) 5 / SecsPerDay; // 5 sec
                Authentication();
            }

            if (m_Status == psRunning) {
                if ((now >= m_CheckDate)) {
                    m_CheckDate = now + (CDateTime) 5 / MinsPerDay; // 5 min
                    CheckOutbox();
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoTimer(CPollEventHandler *AHandler) {
            uint64_t exp;

            auto pTimer = dynamic_cast<CEPollTimer *> (AHandler->Binding());
            pTimer->Read(&exp, sizeof(uint64_t));

            try {
                DoHeartbeat();
            } catch (Delphi::Exception::Exception &E) {
                DoServerEventHandlerException(AHandler, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSend(const CMessage &Message) {
            CStringList SQL;

            api::authorize(SQL, m_MailBot);
            api::execute_object_action(SQL, Message.MessageId(), "send");

            Log()->Message("[%s] Message sending.", Message.MessageId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoCancel(const CMessage &Message, const CString &Error) {
            CStringList SQL;

            api::authorize(SQL, m_MailBot);
            api::execute_object_action(SQL, Message.MessageId(), "cancel");
            api::set_object_label(SQL, Message.MessageId(), Error);

            Log()->Message("[%s] Sent message canceled.", Message.MessageId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoDone(const CMessage &Message) {
            CStringList SQL;

            api::authorize(SQL, m_MailBot);
            api::execute_object_action(SQL, Message.MessageId(), "done");
            if (!Message.MsgId().IsEmpty())
                api::set_object_label(SQL, Message.MessageId(), Message.MsgId());

            Log()->Message("[%s] Message sent successfully.", Message.MessageId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoFail(const CMessage &Message, const CString &Error) {
            CStringList SQL;

            api::authorize(SQL, m_MailBot);
            api::execute_object_action(SQL, Message.MessageId(), "fail");
            api::set_object_label(SQL, Message.MessageId(), Error);

            Log()->Message("[%s] Message was not sent.", Message.MessageId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSMTPConnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            if (Assigned(pConnection)) {
                auto pClient = dynamic_cast<CSMTPClient *> (pConnection->Client());
                if (Assigned(pClient)) {
                    for (int i = 0; i < pClient->Messages().Count(); ++i)
                        DoSend(pClient->Messages()[i]);
                }
                Log()->Message(_T("[%s:%d] SMTP client connected."), pConnection->Socket()->Binding()->PeerIP(),
                               pConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSMTPDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            if (Assigned(pConnection)) {
                if (!pConnection->ClosedGracefully()) {
                    Log()->Message(_T("[%s:%d] SMTP client disconnected."), pConnection->Socket()->Binding()->PeerIP(),
                                   pConnection->Socket()->Binding()->PeerPort());
                } else {
                    Log()->Message(_T("SMTP client disconnected."));
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoAPIConnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection *>(Sender);
            if (Assigned(pConnection)) {
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());
                if (Assigned(pClient)) {
                    auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                    if (Assigned(pMessage)) {
                        DoSend(*pMessage);
                    }
                }
                Log()->Message(_T("[%s:%d] API client connected."), pConnection->Socket()->Binding()->PeerIP(),
                               pConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoAPIDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection *>(Sender);
            if (Assigned(pConnection)) {
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());
                if (Assigned(pClient)) {
                    auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                    delete pMessage;
                }
                if (!pConnection->ClosedGracefully()) {
                    Log()->Message(_T("[%s:%d] API client disconnected."), pConnection->Socket()->Binding()->PeerIP(),
                                   pConnection->Socket()->Binding()->PeerPort());
                } else {
                    Log()->Message(_T("API client disconnected."));
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            auto pConnection = dynamic_cast<CSMTPConnection *> (AConnection);
            auto pClient = dynamic_cast<CSMTPClient *> (pConnection->Client());

            CStringList SQL;

            api::authorize(SQL, m_MailBot);
            for (int i = 0; i < pClient->Messages().Count(); ++i) {
                const auto& Message = pClient->Messages()[i];
                api::set_object_label(SQL, Message.MessageId(), E.what());
            }

            Log()->Error(APP_LOG_ERR, 0, "%s", E.what());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoPostgresNotify(CPQConnection *AConnection, PGnotify *ANotify) {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);
                    CheckMessages(pqResults[QUERY_INDEX_MESSAGE]);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };
#ifdef _DEBUG
            const auto& Info = AConnection->ConnInfo();

            DebugMessage("[NOTIFY] [%d] [postgresql://%s@%s:%s/%s] [PID: %d] [%s] %s\n",
                         AConnection->Socket(), Info["user"].c_str(), Info["host"].c_str(), Info["port"].c_str(), Info["dbname"].c_str(),
                         ANotify->be_pid, ANotify->relname, ANotify->extra);
#endif
            CStringList SQL;

            api::authorize(SQL, m_MailBot);
            api::get_message(SQL, ANotify->extra);

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {
            CPQResult *pResult;
            try {
                for (int I = 0; I < APollQuery->Count(); I++) {
                    pResult = APollQuery->Results(I);

                    if (pResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());
                }
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            DoError(E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSMTPRequest(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            const auto& command = pConnection->Command();
            CMemoryStream Stream;
            command.ToBuffers(Stream);
            CString S;
            S.LoadFromStream(Stream);
            DebugMessage("C: %s", S.c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSMTPReply(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            const auto& command = pConnection->Command();
            DebugMessage("S: %s", command.Reply().Text().c_str());
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}

}
