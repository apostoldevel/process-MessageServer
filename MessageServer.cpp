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

#define PROVIDER_NAME "google"
#define FIREBASE_APPLICATION_NAME "firebase"
#define PROVIDER_APPLICATION_NAME "service"
#define CONFIG_SECTION_NAME "process/MessageServer"

#define MAIL_BOT_USERNAME "mailbot"
#define API_BOT_USERNAME "apibot"

#define QUERY_INDEX_AUTH    0
#define QUERY_INDEX_SU      1
#define QUERY_INDEX_MESSAGE 2

extern "C++" {

namespace Apostol {

    namespace Processes {

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageServer ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CMessageServer::CMessageServer(CCustomProcess *AParent, CApplication *AApplication):
                inherited(AParent, AApplication, "message server") {

            m_Agent = CString().Format("Message Server (%s)", Application()->Title().c_str());
            m_Host = CApostolModule::GetIPByHostName(CApostolModule::GetHostName());

            const auto now = Now();

            m_AuthDate = now;
            m_FixedDate = now;
            m_CheckDate = now;

            m_HeartbeatInterval = 5000;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::LoadFCMConfig(const CString &FileName) {

            const CString Prefix(Config()->Prefix());
            CString ConfigFile(FileName);

            if (!path_separator(ConfigFile.front())) {
                ConfigFile = Prefix + ConfigFile;
            }

            m_Providers.Clear();

            const CString providerName(PROVIDER_NAME);

            if (FileExists(ConfigFile.c_str())) {
                int Index = m_Providers.AddPair(providerName, CProvider());
                auto& Provider = m_Providers[Index].Value();
                CJSONObject Json;
                Json.LoadFromFile(ConfigFile.c_str());
                Provider.Name = providerName;
                Provider.Params.Object().AddPair(FIREBASE_APPLICATION_NAME, Json);
            } else {
                Log()->Error(APP_LOG_WARN, 0, APP_FILE_NOT_FOUND, ConfigFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::LoadSMTPConfig(const CString &FileName) {

            const CString Prefix(Config()->Prefix());
            CString ConfigFile(FileName);

            if (!path_separator(ConfigFile.front())) {
                ConfigFile = Prefix + ConfigFile;
            }

            m_Configs.Clear();

            if (FileExists(ConfigFile.c_str())) {
                CIniFile IniFile(ConfigFile.c_str());
                IniFile.OnIniFileParseError(OnIniFileParseError);

                CStringList Sections;
                IniFile.ReadSections(&Sections);

                for (int i = 0; i < Sections.Count(); i++) {
                    const auto& Section = Sections[i];
                    int Index = m_Configs.AddPair(Section, CSMTPConfig());
                    auto& Config = m_Configs[Index].Value();
                    InitSMTPConfig(IniFile, Section, Config);
                }

                auto& defaultConfig = m_Configs.Default();
                if (defaultConfig.Name().IsEmpty()) {
                    defaultConfig.Name() = _T("default");
                    auto& Config = defaultConfig.Value();
                    InitSMTPConfig(IniFile, defaultConfig.Name(), Config);
                }
            } else {
                Log()->Error(APP_LOG_WARN, 0, APP_FILE_NOT_FOUND, ConfigFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitSMTPConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config) {
            Config.Location() = IniFile.ReadString(Section, "host", "localhost:25");
            Config.UserName() = IniFile.ReadString(Section, "username", "smtp");
            Config.Password() = IniFile.ReadString(Section, "password", "smtp");
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitM2MConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config) {
            Config.AddPair("uri", IniFile.ReadString(Profile, "uri", "https://api.mcommunicator.ru/m2m/m2m_api.asmx"));
            Config.AddPair("apikey", IniFile.ReadString(Profile, "apikey", ""));
            Config.AddPair("naming", IniFile.ReadString(Profile, "naming", ""));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitSBAConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config) {
            Config.AddPair("uri", IniFile.ReadString(Profile, "uri", Profile == "test" ? "https://3dsec.sberbank.ru" : "https://securepayments.sberbank.ru"));
            Config.AddPair("username", IniFile.ReadString(Profile, "username", ""));
            Config.AddPair("password", IniFile.ReadString(Profile, "password", ""));
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

        void CMessageServer::BeforeRun() {
            sigset_t set;

            Application()->Header(Application()->Name() + ": message server");

            Log()->Debug(0, MSG_PROCESS_START, GetProcessName(), Application()->Header().c_str());

            InitSignals();

            Reload();

            SetUser(Config()->User(), Config()->Group());

            InitializePQServer(Application()->Title());

            PQServerStart("helper");

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

                log_debug0(APP_LOG_DEBUG_EVENT, Log(), 0, "message server cycle");

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
                        Log()->Error(APP_LOG_NOTICE, 0, "gracefully shutting down");
                        Application()->Header("message server is shutting down");
                    }

                    //DoExit();

                    if (!sig_exiting) {
                        sig_exiting = 1;
                    }
                }

                if (sig_reconfigure) {
                    sig_reconfigure = 0;
                    Log()->Error(APP_LOG_NOTICE, 0, "reconfiguring");

                    Reload();
                }

                if (sig_reopen) {
                    sig_reopen = 0;
                    Log()->Error(APP_LOG_NOTICE, 0, "reopening logs");
                }
            }

            Log()->Error(APP_LOG_NOTICE, 0, "stop message server");
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Reload() {
            CServerProcess::Reload();

            LoadSMTPConfig(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, "smtp", "conf/smtp.conf"));
            LoadFCMConfig(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, "fcm", "conf/fcm.json"));

            LoadConfig(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, "m2m", "conf/m2m.conf"), m_M2MProfiles, InitM2MConfig);
            LoadConfig(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, "sba", "conf/sba.conf"), m_SBAProfiles, InitSBAConfig);

            const auto now = Now();

            m_AuthDate = now;
            m_FixedDate = now;
            m_CheckDate = now;
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

                CPQueryResults Result;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, Result);

                    m_Session = Result[0][0]["session"];
                    m_Secret = Result[0][0]["secret"];

                    m_AuthDate = Now() + (CDateTime) 24 / HoursPerDay;
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            CString Application(PROVIDER_APPLICATION_NAME);

            const auto &Providers = Server().Providers();
            const auto &Provider = Providers.DefaultValue();

            m_ClientId = Provider.ClientId(Application);
            m_ClientSecret = Provider.Secret(Application);

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM api.login(%s, %s, %s, %s);",
                                     PQQuoteLiteral(m_ClientId).c_str(),
                                     PQQuoteLiteral(m_ClientSecret).c_str(),
                                     PQQuoteLiteral(m_Agent).c_str(),
                                     PQQuoteLiteral(m_Host).c_str()
            ));

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Authorize(CStringList &SQL, const CString &Session, const CString &Username, const CString &Secret) {
            SQL.Add(CString().Format("SELECT * FROM api.authorize(%s);",
                                     PQQuoteLiteral(Session).c_str()
            ));

            SQL.Add(CString().Format("SELECT * FROM api.su(%s, %s);",
                                     PQQuoteLiteral(Username).c_str(),
                                     PQQuoteLiteral(Secret).c_str()
            ));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::ExecuteObjectAction(CStringList &SQL, const CString &MsgId, const CString &Action) {
            SQL.Add(CString().Format("SELECT * FROM api.execute_object_action(%s, %s);",
                                     MsgId.c_str(),
                                     PQQuoteLiteral(Action).c_str()
            ));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SetArea(CStringList &SQL, const CString &Area) {
            SQL.Add(CString().Format("SELECT * FROM api.set_session_area(%s);",
                                     Area.c_str()
            ));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SetObjectLabel(CStringList &SQL, const CString &MsgId, const CString &Label) {
            SQL.Add(CString().Format("SELECT * FROM api.set_object_label(%s, %s);",
                                     MsgId.c_str(),
                                     PQQuoteLiteral(Label).c_str()
            ));
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CMessageServer::CreateGoogleToken(const CProvider &Provider, const CString &Application) {

            const auto& private_key = std::string(Provider.Params[Application]["private_key"].AsString());

            const auto& kid = std::string(Provider.Params[Application]["private_key_id"].AsString());
            const auto& public_key = std::string(OAuth2::Helper::GetPublicKey(m_Providers, kid));

            const auto& iss = std::string(Provider.Params[Application]["client_email"].AsString());
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

        void CMessageServer::ProviderAccessToken(const CProvider &Provider) {

            auto OnDone = [this](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                const CJSON Json(pReply->Content);

                m_Tokens.Values("fcm_token", Json["access_token"].AsString());

                return true;
            };

            const auto &token_uri = Provider.TokenURI(FIREBASE_APPLICATION_NAME);
            const auto &service_token = CreateGoogleToken(Provider, FIREBASE_APPLICATION_NAME);

            m_Tokens.Values("service_token", service_token);

            FetchAccessToken(token_uri, service_token, OnDone);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::FetchCerts(CProvider &Provider) {

            const auto& URI = Provider.CertURI(FIREBASE_APPLICATION_NAME);

            if (URI.IsEmpty()) {
                Log()->Error(APP_LOG_INFO, 0, _T("Certificate URI in provider \"%s\" is empty."), Provider.Name.c_str());
                return;
            }

            Log()->Error(APP_LOG_INFO, 0, _T("Trying to fetch public keys from: %s"), URI.c_str());

            auto OnRequest = [&Provider](CHTTPClient *Sender, CHTTPRequest *ARequest) {
                const auto& client_x509_cert_url = std::string(Provider.Params[FIREBASE_APPLICATION_NAME]["client_x509_cert_url"].AsString());

                Provider.KeyStatusTime = Now();
                Provider.KeyStatus = CProvider::ksFetching;

                CLocation Location(client_x509_cert_url);
                CHTTPRequest::Prepare(ARequest, "GET", Location.pathname.c_str());
            };

            auto OnExecute = [this, &Provider](CTCPConnection *AConnection) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pReply = pConnection->Reply();

                try {
                    DebugRequest(pConnection->Request());
                    DebugReply(pReply);

                    Provider.KeyStatusTime = Now();

                    Provider.Keys.Clear();
                    Provider.Keys << pReply->Content;

                    Provider.KeyStatus = CProvider::ksSuccess;

                    ProviderAccessToken(Provider);
                } catch (Delphi::Exception::Exception &E) {
                    Provider.KeyStatus = CProvider::ksFailed;
                    Log()->Error(APP_LOG_ERR, 0, "[Certificate] Message: %s", E.what());
                }

                pConnection->CloseConnection(true);
                return true;
            };

            auto OnException = [&Provider](CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                Provider.KeyStatusTime = Now();
                Provider.KeyStatus = CProvider::ksFailed;

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
            auto& Provider = m_Providers[PROVIDER_NAME];
            if (Provider.ApplicationExists(FIREBASE_APPLICATION_NAME)) {
                if (Provider.KeyStatus == CProvider::ksUnknown) {
                    FetchCerts(Provider);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckProviders() {
            auto& Provider = m_Providers[PROVIDER_NAME];
            if (Provider.ApplicationExists(FIREBASE_APPLICATION_NAME)) {
                if (Provider.KeyStatus != CProvider::ksUnknown) {
                    Provider.KeyStatusTime = Now();
                    Provider.KeyStatus = CProvider::ksUnknown;
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

            Message.MsgId() = id;
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

        void CMessageServer::SendFCM(const CStringPairs &Record) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &fcm_token = Sender->Data()["fcm_token"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/json"));

                ARequest->AddHeader("Authorization", "Bearer " + fcm_token);

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
                        pMessage->MessageId() = Json["name"].AsString();
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

            auto pMessage = new CMessage();

            pMessage->MsgId() = id;
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
            CLocation URI(CString().Format("https://fcm.googleapis.com/v1/projects/%s/messages:send", profile.c_str()));

            auto pClient = GetClient(URI.hostname, URI.port);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("fcm_token", m_Tokens["fcm_token"]);

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

        void CMessageServer::SendM2M(const CStringPairs &Record) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &apikey = Sender->Data()["apikey"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/soap+xml; charset=utf-8"));

                ARequest->AddHeader("Authorization", "Bearer " + apikey);

                DebugRequest(ARequest);
            };

            auto OnExecute = [this](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {

                    const auto& Agent = pClient->Data()["agent"];
                    const auto& Area = pClient->Data()["area"];

                    CStringList SQL;

                    Authorize(SQL, m_Session, API_BOT_USERNAME, m_ClientSecret);
                    SetArea(SQL, Area);

                    SQL.Add(CString().Format("SELECT * FROM api.set_message(null, %s, 'message.inbox', %s, %s, %s, %s, %s);",
                                             PQQuoteLiteral(pMessage->MsgId()).c_str(),
                                             PQQuoteLiteral(Agent).c_str(),
                                             PQQuoteLiteral(pMessage->From()).c_str(),
                                             PQQuoteLiteral(pMessage->To().First()).c_str(),
                                             PQQuoteLiteral(pMessage->Subject()).c_str(),
                                             PQQuoteLiteral(pReply->Content).c_str()
                    ));

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

            pMessage->MsgId() = id;
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
            const auto& uri = m_M2MProfiles[profile]["uri"];
            const auto& apikey = m_M2MProfiles[profile]["apikey"];
            const auto& naming = m_M2MProfiles[profile]["naming"];

            CLocation URI(uri);

            auto pClient = GetClient(URI.hostname, URI.port);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("apikey", apikey);
            pClient->Data().Values("naming", naming);

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

        void CMessageServer::SendSBA(const CStringPairs &Record) {

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

                    const auto& Agent = pClient->Data()["agent"];
                    const auto& Area = pClient->Data()["area"];

                    CStringList SQL;

                    Authorize(SQL, m_Session, API_BOT_USERNAME, m_ClientSecret);
                    SetArea(SQL, Area);

                    SQL.Add(CString().Format("SELECT * FROM api.set_message(null, %s, 'message.inbox', %s, %s, %s, %s, %s);",
                                             PQQuoteLiteral(pMessage->MsgId()).c_str(),
                                             PQQuoteLiteral(Agent).c_str(),
                                             PQQuoteLiteral(pMessage->From()).c_str(),
                                             PQQuoteLiteral(pMessage->To().First()).c_str(),
                                             PQQuoteLiteral(pMessage->Subject()).c_str(),
                                             PQQuoteLiteral(pReply->Content).c_str()
                    ));

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

            pMessage->MsgId() = id;
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
            const auto& uri = m_SBAProfiles[profile]["uri"] + (address.front() == '/' ? address : '/' + address);
            const auto& userName = m_SBAProfiles[profile]["username"];
            const auto& password = m_SBAProfiles[profile]["password"];

            CLocation URI(uri);

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
                const auto &agent = Record.Values("agentcode");

                if (agent == "smtp.agent") {
                    SendSMTP(Record);
                } else if (agent == "fcm.agent" && !m_Tokens["fcm_token"].IsEmpty()) {
                    SendFCM(Record);
                } else if (agent == "m2m.agent") {
                    SendM2M(Record);
                } else if (agent == "sba.agent") {
                    SendSBA(Record);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckOutbox() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults Results;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, Results);
                    CheckMessages(Results[QUERY_INDEX_MESSAGE]);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            CStringList SQL;

            Authorize(SQL, m_Session, MAIL_BOT_USERNAME, m_ClientSecret);

            SQL.Add("SELECT * FROM api.outbox('prepared') ORDER BY created;");

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

            m_AuthDate = now + (CDateTime) m_HeartbeatInterval / MSecsPerDay;
            m_CheckDate = now + (CDateTime) m_HeartbeatInterval * 2 / MSecsPerDay;

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
                Authentication();
            }

            if (!m_Session.IsEmpty()) {
                if ((now >= m_CheckDate)) {
                    m_CheckDate = now + (CDateTime) 5 / MinsPerDay; // 5 min
                    CheckOutbox();
                }
            }

            m_MailManager.CleanUp();
            m_ClientManager.CleanUp();
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

            Authorize(SQL, m_Session, MAIL_BOT_USERNAME, m_ClientSecret);
            ExecuteObjectAction(SQL, Message.MsgId(), "send");

            Log()->Message("[%s] Message sending.", Message.MsgId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoCancel(const CMessage &Message, const CString &Error) {
            CStringList SQL;

            Authorize(SQL, m_Session, MAIL_BOT_USERNAME, m_ClientSecret);
            ExecuteObjectAction(SQL, Message.MsgId(), "cancel");
            SetObjectLabel(SQL, Message.MsgId(), Error);

            Log()->Message("[%s] Sent message canceled.", Message.MsgId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoDone(const CMessage &Message) {
            CStringList SQL;

            Authorize(SQL, m_Session, MAIL_BOT_USERNAME, m_ClientSecret);
            ExecuteObjectAction(SQL, Message.MsgId(), "done");
            if (!Message.MessageId().IsEmpty())
                SetObjectLabel(SQL, Message.MsgId(), Message.MessageId());

            Log()->Message("[%s] Message sent successfully.", Message.MsgId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoFail(const CMessage &Message, const CString &Error) {
            CStringList SQL;

            Authorize(SQL, m_Session, MAIL_BOT_USERNAME, m_ClientSecret);
            ExecuteObjectAction(SQL, Message.MsgId(), "fail");
            SetObjectLabel(SQL, Message.MsgId(), Error);

            Log()->Message("[%s] Message was not sent.", Message.MsgId().c_str());

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

            Authorize(SQL, m_Session, MAIL_BOT_USERNAME, m_ClientSecret);
            for (int i = 0; i < pClient->Messages().Count(); ++i) {
                const auto& Message = pClient->Messages()[i];
                SetObjectLabel(SQL, Message.MsgId(), E.what());
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

                CPQueryResults Results;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, Results);
                    CheckMessages(Results[QUERY_INDEX_MESSAGE]);
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

            Authorize(SQL, m_Session, MAIL_BOT_USERNAME, m_ClientSecret);

            SQL.Add(CString().Format("SELECT * FROM api.get_message(%s);", ANotify->extra));

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
            command.ToBuffers(&Stream);
            CString S;
            S.LoadFromStream(&Stream);
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
