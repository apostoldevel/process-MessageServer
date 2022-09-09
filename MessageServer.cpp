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
#include "Connector.hpp"
#include "MessageServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

#define CONFIG_SECTION_NAME "process/MessageServer"

#define API_BOT_USERNAME "apibot"

#define QUERY_INDEX_AUTH     0
#define QUERY_INDEX_DATA     1

#define SLEEP_SECOND_AFTER_ERROR 10

#define PG_LISTEN_NAME "outbox"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Processes {

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageHandler --------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CMessageHandler::CMessageHandler(CMessageServer *AServer, const CString &Session, const CString &MessageId,
                COnMessageHandlerEvent &&Handler): CPollConnection(&AServer->QueueManager()), m_Allow(true) {

            m_pServer = AServer;
            m_Session = Session;
            m_MessageId = MessageId;
            m_Handler = Handler;

            AddToQueue();
        }
        //--------------------------------------------------------------------------------------------------------------

        CMessageHandler::~CMessageHandler() {
            RemoveFromQueue();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageHandler::Close() {
            RemoveFromQueue();
        }
        //--------------------------------------------------------------------------------------------------------------

        int CMessageHandler::AddToQueue() {
            return m_pServer->AddToQueue(this);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageHandler::RemoveFromQueue() {
            m_pServer->RemoveFromQueue(this);
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CMessageHandler::Handler() {
            if (m_Allow && m_Handler) {
                m_Handler(this);
                return true;
            }
            return false;
        }

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
            m_MaxMessagesQueue = Config()->PostgresPollMin();

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

            InitializePQClients(Application()->Title(), 1, m_MaxMessagesQueue);

            SigProcMask(SIG_UNBLOCK, SigAddSet(&set));

            SetTimerInterval(1000);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::AfterRun() {
            CApplicationProcess::AfterRun();
            PQClientsStop();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Run() {
            auto &PQClient = PQClientStart(_T("helper"));

            while (!sig_exiting) {

                Log()->Debug(APP_LOG_DEBUG_EVENT, _T("message server cycle"));

                try {
                    PQClient.Wait();
                } catch (Delphi::Exception::Exception &E) {
                    Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
                }

                if (sig_terminate || sig_quit) {
                    if (sig_quit) {
                        sig_quit = 0;
                        Log()->Debug(APP_LOG_DEBUG_EVENT, _T("gracefully shutting down"));
                        Application()->Header(_T("message server is shutting down"));
                    }

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

        void CMessageServer::CreateAccessToken(const CProvider &Provider, const CString &Application, CStringList &Tokens) {

            auto OnDone = [&Tokens](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                const CJSON Json(pReply->Content);

                Tokens.Values("access_token", Json["access_token"].AsString());

                return true;
            };

            auto OnHTTPClient = [this](const CLocation &URI) {
                return GetClient(URI.hostname, URI.port);
            };
            //----------------------------------------------------------------------------------------------------------

            CString server_uri("http://localhost:");
            server_uri << (int) Config()->Port();

            const auto &token_uri = Provider.TokenURI(Application);
            const auto &service_token = Application == FIREBASE_APPLICATION_NAME ? CToken::CreateGoogleToken(Provider, Application) : CToken::CreateToken(Provider, Application);

            Tokens.Values("service_token", service_token);

            if (!token_uri.IsEmpty()) {
                CToken::FetchAccessToken(token_uri.front() == '/' ? server_uri + token_uri : token_uri, service_token, OnHTTPClient, OnDone);
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

            auto OnException = [this, &Provider](CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                Provider.KeyStatusTime(Now());
                Provider.KeyStatus(ksFailed);

                m_FixedDate = Now() + (CDateTime) 5 / SecsPerDay; // 5 sec

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

        int CMessageServer::IndexOfMessage(const CString &MessageId) {
            for (int i = 0; i < m_QueueManager.Count(); ++i) {
                auto pMessageHandler = dynamic_cast<CMessageHandler *> (m_QueueManager[i]);
                if (pMessageHandler != nullptr) {
                    if (pMessageHandler->MessageId() == MessageId)
                        return i;
                }
            }
            return -1;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CMessageServer::InQueue(const CString &MessageId) {
            return IndexOfMessage(MessageId) != -1;
        }
        //--------------------------------------------------------------------------------------------------------------

        CMessageHandler *CMessageServer::GetMessageHandler(const CString &MessageId) {
            const auto index = IndexOfMessage(MessageId);
            if (index != -1)
                return dynamic_cast<CMessageHandler *> (m_QueueManager[index]);
            return nullptr;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CMessageServer::IndexOfProgress(const CString &MessageId) {
            return m_Progress.IndexOf(MessageId);
        }
        //--------------------------------------------------------------------------------------------------------------

        int CMessageServer::AddProgress(const CString &MessageId) {
            const auto index = IndexOfProgress(MessageId);
            if (index == -1)
                return m_Progress.Add(MessageId);
            return index;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DeleteProgress(const CString &MessageId) {
            const auto index = IndexOfProgress(MessageId);
            if (index != -1)
                m_Progress.Delete(index);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DeleteHandler(CMessageHandler *AHandler) {
            if (AHandler != nullptr) {
                DeleteProgress(AHandler->MessageId());
            }
            delete AHandler;
            UnloadMessageQueue();
        }
        //--------------------------------------------------------------------------------------------------------------

        int CMessageServer::AddToQueue(CMessageHandler *AHandler) {
            return m_Queue.AddToQueue(this, AHandler);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InsertToQueue(int Index, CMessageHandler *AHandler) {
            m_Queue.InsertToQueue(this, Index, AHandler);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::RemoveFromQueue(CMessageHandler *AHandler) {
            m_Queue.RemoveFromQueue(this, AHandler);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::UnloadMessageQueue() {
            const auto index = m_Queue.IndexOf(this);
            if (index != -1) {
                const auto pQueue = m_Queue[index];
                for (int i = 0; i < pQueue->Count(); ++i) {
                    auto pHandler = (CMessageHandler *) pQueue->Item(i);
                    if (pHandler != nullptr) {
                        pHandler->Handler();
                    }
                    if (m_Progress.Count() >= m_MaxMessagesQueue)
                        break;
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config) {
            IniFile.ReadSectionValues(Profile.c_str(), &Config);
        }
        //--------------------------------------------------------------------------------------------------------------

        CSMTPClient *CMessageServer::GetSMTPClient(const CSMTPConfig &Config) {

            auto pClient = m_MailManager.Add(Config);

            pClient->AllocateEventHandlers(GetPQClient());

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

            m_Sessions.Clear();
            m_Queue.Clear();
            m_Progress.Clear();
            m_Configs.Clear();
            m_Providers.Clear();
            m_Profiles.Clear();
            m_Tokens.Clear();

            m_AuthDate = 0;
            m_FixedDate = 0;
            m_CheckDate = 0;

            m_Status = psStopped;

            CStringList Configs;
            Config()->IniFile().ReadSection(CONFIG_SECTION_NAME, &Configs);

            for (int i = 0; i < Configs.Count(); ++i) {
                const auto& config = Configs[i].Lower();

                if (config == "enable")
                    continue;

                if (config == "smtp") {
                    Connectors::CSMTPConnector::Load(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, config, CString().Format("conf/%s.conf", config.c_str())), m_Configs);
                } else {
                    m_Profiles.AddPair(config, CStringListPairs());
                    Connectors::CCommonConnector::Load(Config()->IniFile().ReadString(CONFIG_SECTION_NAME, config, CString().Format("conf/%s.conf", config.c_str())), m_Profiles[config]);
                }
            }

            for (int i = 0; i < m_Profiles.Count(); ++i) {
                const auto &profile = m_Profiles[i].Value();
                for (int j = 0; j < profile.Count(); ++j) {
                    const auto &config = profile[j].Value();
                    const auto &oauth2 = config["oauth2"];
                    if (!oauth2.IsEmpty()) {
                        const auto &server = config["server"];
                        const auto &provider = config["provider"];
                        const auto &application = config["application"];
                        m_Tokens.AddPair(provider, CStringList());
                        LoadOAuth2(oauth2, provider.empty() ? SYSTEM_PROVIDER_NAME : provider, application.empty() ? SERVICE_APPLICATION_NAME : application, m_Providers);
                    }
                }
            }

            Log()->Notice("[%s] Successful reloading", CONFIG_SECTION_NAME);
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

                    APollQuery->Connection()->Listeners().Add(PG_LISTEN_NAME);
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

            SQL.Add("LISTEN " PG_LISTEN_NAME ";");

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckListen() {
            if (!GetPQClient().CheckListen(PG_LISTEN_NAME))
                InitListen();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Authentication() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);

                    const auto &login = pqResults[0];
                    const auto &sessions = pqResults[1];

                    const auto &session = login.First()["session"];

                    m_Sessions.Clear();
                    for (int i = 0; i < sessions.Count(); ++i) {
                        m_Sessions.Add(sessions[i]["get_sessions"]);
                    }

                    m_AuthDate = Now() + (CDateTime) 24 / HoursPerDay;
                    m_Status = psRunning;

                    SignOut(session);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            const auto &caProviders = Server().Providers();
            const auto &caProvider = caProviders.DefaultValue();

            const auto &clientId = caProvider.ClientId(SERVICE_APPLICATION_NAME);
            const auto &clientSecret = caProvider.Secret(SERVICE_APPLICATION_NAME);

            CStringList SQL;

            api::login(SQL, clientId, clientSecret, m_Agent, m_Host);
            api::get_sessions(SQL, API_BOT_USERNAME, m_Agent, m_Host);

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SignOut(const CString &Session) {
            CStringList SQL;

            api::signout(SQL, Session);

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendMessage(CMessageHandler *AHandler, const TPairs<CString> &Message) {

            auto OnSMTPClient = [this, AHandler](const CSMTPConfig &Config) {
                auto pClient = GetSMTPClient(Config);
                pClient->AutoFree(true);
                pClient->Data().Values("session", AHandler->Session());
                return pClient;
            };
            //----------------------------------------------------------------------------------------------------------

            auto OnHTTPClient = [this, AHandler](const CLocation &URI) {
                auto pClient = GetClient(URI.hostname, URI.port);
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                pClient->OnConnected([this](auto &&Sender) { DoAPIConnected(Sender); });
                pClient->OnDisconnected([this](auto &&Sender) { DoAPIDisconnected(Sender); });
#else
                pClient->OnConnected(std::bind(&CMessageServer::DoAPIConnected, this, _1));
                pClient->OnDisconnected(std::bind(&CMessageServer::DoAPIDisconnected, this, _1));
#endif
                pClient->AutoFree(true);

                return pClient;
            };
            //----------------------------------------------------------------------------------------------------------

            auto OnDone = [this](const CMessage &Message) {
                DoDone(Message);
            };
            //----------------------------------------------------------------------------------------------------------

            auto OnFail = [this](const CMessage &Message, const CString &Error) {
                DoFail(Message, Error);
            };
            //----------------------------------------------------------------------------------------------------------

            auto OnFCMExecute = [](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    const CJSON Json(pReply->Content);

                    if (Json.HasOwnProperty("error")) {
                        const auto& error = Json["error"];
                        const auto& code = error["code"].AsInteger();
                        const auto& message = error["message"].AsString();
                        const auto& status = error["status"].AsString();

                        pMessage->Fail(CString().Format("[%d] %s: %s", code, status.c_str(), message.c_str()));
                    } else {
                        pMessage->MsgId() = Json["name"].AsString();
                        pMessage->Done();
                    }
                }

                return true;
            };
            //----------------------------------------------------------------------------------------------------------

            auto OnAPIExecute = [this](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {

                    const auto& agent = pClient->Data()["agent"];
                    const auto& area = pClient->Data()["area"];

                    CStringList SQL;

                    api::authorize(SQL, pMessage->Session());
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
            //----------------------------------------------------------------------------------------------------------

            auto OnException = [](CTCPConnection *Sender, const Delphi::Exception::Exception &E) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                DebugReply(pConnection->Reply());

                const auto& host = pClient->Host();

                Log()->Error(APP_LOG_ERR, 0, "[%s:%d] %s", host.empty() ? "unknown" : host.c_str(), pClient->Port(), E.what());

                auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                if (pMessage != nullptr) {
                    pMessage->Fail(E.what());
                }
            };

            //----------------------------------------------------------------------------------------------------------

            //----------------------------------------------------------------------------------------------------------

            //----------------------------------------------------------------------------------------------------------

            const auto &type = Message["agenttypecode"];
            const auto &agent = Message["agentcode"];

            if (type == "email.agent") {
                if (agent == "smtp.agent") {
                    Connectors::CSMTPConnector::Send(AHandler->Session(), Message, m_Configs, OnSMTPClient, OnDone, OnFail);
                } else {
                    DeleteHandler(AHandler);
                }
            } else if (type == "api.agent") {
                if (agent == "fcm.agent") {
                    Connectors::CFCMConnector::Send(AHandler->Session(), Message, m_Profiles["fcm"], m_Tokens, OnHTTPClient, OnFCMExecute, OnException, OnDone, OnFail);
                } else if (agent == "m2m.agent") {
                    Connectors::CM2MConnector::Send(AHandler->Session(), Message, m_Profiles["m2m"], m_Tokens, OnHTTPClient, OnAPIExecute, OnException, OnDone, OnFail);
                } else if (agent == "sba.agent") {
                    Connectors::CSBAConnector::Send(AHandler->Session(), Message, m_Profiles["sba"], m_Tokens, OnHTTPClient, OnAPIExecute, OnException, OnDone, OnFail);
                } else if (agent != "bm.agent") {
                    Connectors::CAPIConnector::Send(AHandler->Session(), Message, m_Profiles["api"], m_Tokens, OnHTTPClient, OnAPIExecute, OnException, OnDone, OnFail);
                } else {
                    DeleteHandler(AHandler);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendMessages(const CString &Session, const CPQueryResult& Messages) {
            for (int i = 0; i < Messages.Count(); ++i) {
                const auto &message = Messages[i];
                const auto &id = message["id"];
                if (!InQueue(id)) {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    new CMessageHandler(this, Session, id, [this](auto &&Id) { DoMessage(Id); });
#else
                    new CMessageHandler(this, Session, id, std::bind(&CMessageServer::DoMessage, this, _1));
#endif
                }
            }
            UnloadMessageQueue();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckOutbox() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;
                CStringList SQL;

                const auto &session = APollQuery->Data()["session"];

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);

                    const auto &authorize = pqResults[QUERY_INDEX_AUTH].First();

                    if (authorize["authorized"] != "t")
                        throw Delphi::Exception::ExceptionFrm("Authorization failed: %s", authorize["message"].c_str());

                    SendMessages(session, pqResults[QUERY_INDEX_DATA]);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            for (int i = 0; i < m_Sessions.Count(); ++i) {
                const auto &session = m_Sessions[i];

                CStringList SQL;

                api::authorize(SQL, session);
                api::outbox(SQL, "prepared");

                try {
                    auto pQuery = ExecSQL(SQL, nullptr, OnExecuted, OnException);
                    pQuery->Data().AddPair("session", session);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoError(const Delphi::Exception::Exception &E) {
            m_AuthDate = Now() + (CDateTime) SLEEP_SECOND_AFTER_ERROR / SecsPerDay; // 10 sec;
            m_CheckDate = m_AuthDate;

            m_Status = psStopped;

            Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            Log()->Notice("Continue after %d seconds", SLEEP_SECOND_AFTER_ERROR);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::Heartbeat(CDateTime Now) {
            if ((Now >= m_FixedDate)) {
                m_FixedDate = Now + (CDateTime) 55 / MinsPerDay; // 55 min
                CheckProviders();
                FetchProviders();
            }

            if ((Now >= m_AuthDate)) {
                m_AuthDate = Now + (CDateTime) 5 / SecsPerDay; // 5 sec
                Authentication();
            }

            if (m_Status == psRunning) {
                UnloadMessageQueue();
                if ((Now >= m_CheckDate)) {
                    m_CheckDate = Now + (CDateTime) 1 / MinsPerDay; // 1 min
                    CheckListen();
                    if (m_Queue.IndexOf(this) == -1) {
                        CheckOutbox();
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoMessage(CMessageHandler *AHandler) {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;
                CStringList SQL;

                auto pHandler = dynamic_cast<CMessageHandler *> (APollQuery->Binding());

                if (pHandler == nullptr) {
                    return;
                }

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);
                    const auto &messages = pqResults[QUERY_INDEX_DATA];
                    if (messages.Count() > 0) {
                        for (int i = 0; i < messages.Count(); ++i) {
                            SendMessage(pHandler, messages[i]);
                        }
                    } else {
                        DeleteHandler(pHandler);
                    }
                } catch (Delphi::Exception::Exception &E) {
                    Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
                    DeleteHandler(pHandler);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                auto pHandler = dynamic_cast<CMessageHandler *> (APollQuery->Binding());
                DeleteHandler(pHandler);
                DoError(E);
            };

            if (IndexOfProgress(AHandler->MessageId()) >= 0) {
                Log()->Error(APP_LOG_WARN, 0, "Message %s already in progress.", AHandler->MessageId().c_str());
                DeleteHandler(AHandler);
                return;
            }

            CStringList SQL;

            api::authorize(SQL, AHandler->Session());
            api::get_service_message(SQL, AHandler->MessageId());

            try {
                ExecSQL(SQL, AHandler, OnExecuted, OnException);
                AddProgress(AHandler->MessageId());
                AHandler->Allow(false);
            } catch (Delphi::Exception::Exception &E) {
                DeleteHandler(AHandler);
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoTimer(CPollEventHandler *AHandler) {
            uint64_t exp;

            auto pTimer = dynamic_cast<CEPollTimer *> (AHandler->Binding());
            pTimer->Read(&exp, sizeof(uint64_t));

            try {
                Heartbeat(AHandler->TimeStamp());
            } catch (Delphi::Exception::Exception &E) {
                DoServerEventHandlerException(AHandler, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSend(const CMessage &Message) {
            CStringList SQL;

            api::authorize(SQL, Message.Session());
            api::execute_object_action(SQL, Message.MessageId(), "send");

            Log()->Message("[%s] Message sending...", Message.MessageId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoCancel(const CMessage &Message, const CString &Error) {
            CStringList SQL;

            api::authorize(SQL, Message.Session());
            api::set_object_label(SQL, Message.MessageId(), Error);
            api::execute_object_action(SQL, Message.MessageId(), "cancel");

            Log()->Message("[%s] Sent message canceled.", Message.MessageId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoDone(const CMessage &Message) {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {
                auto pHandler = dynamic_cast<CMessageHandler *> (APollQuery->Binding());
                DeleteHandler(pHandler);
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                auto pHandler = dynamic_cast<CMessageHandler *> (APollQuery->Binding());
                DeleteHandler(pHandler);
                DoError(E);
            };

            CStringList SQL;

            api::authorize(SQL, Message.Session());

            if (!Message.MsgId().IsEmpty()) {
                api::set_object_label(SQL, Message.MessageId(), Message.MsgId());
            }

            api::execute_object_action(SQL, Message.MessageId(), "done");

            Log()->Message("[%s] Message sent successfully.", Message.MessageId().c_str());

            try {
                ExecSQL(SQL, GetMessageHandler(Message.MessageId()), OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoFail(const CMessage &Message, const CString &Error) {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {
                auto pHandler = dynamic_cast<CMessageHandler *> (APollQuery->Binding());
                DeleteHandler(pHandler);
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                auto pHandler = dynamic_cast<CMessageHandler *> (APollQuery->Binding());
                DeleteHandler(pHandler);
                DoError(E);
            };

            CStringList SQL;

            api::authorize(SQL, Message.Session());
            api::set_object_label(SQL, Message.MessageId(), Error);
            api::execute_object_action(SQL, Message.MessageId(), "fail");

            Log()->Message("[%s] Message was not sent.", Message.MessageId().c_str());

            try {
                ExecSQL(SQL, GetMessageHandler(Message.MessageId()), OnExecuted, OnException);
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
                Log()->Notice(_T("[%s:%d] SMTP client connected."), pConnection->Socket()->Binding()->PeerIP(),
                               pConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSMTPDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            if (Assigned(pConnection)) {
                if (!pConnection->ClosedGracefully()) {
                    Log()->Notice(_T("[%s:%d] SMTP client disconnected."), pConnection->Socket()->Binding()->PeerIP(),
                                   pConnection->Socket()->Binding()->PeerPort());
                } else {
                    Log()->Notice(_T("SMTP client disconnected."));
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoAPIConnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection *>(Sender);
            if (Assigned(pConnection)) {
                auto pSocket = pConnection->Socket();
                if (pSocket != nullptr) {
                    auto pHandle = pSocket->Binding();
                    if (pHandle != nullptr) {
                        Log()->Notice(_T("[%s:%d] API client connected."), pHandle->PeerIP(), pHandle->PeerPort());
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoAPIDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection *>(Sender);
            if (Assigned(pConnection)) {
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());
                if (Assigned(pClient)) {
                    auto pMessage = dynamic_cast<CMessage *> (pClient->Data().Objects("message"));
                    chASSERT(pMessage);
                    delete pMessage;
                }
                auto pSocket = pConnection->Socket();
                if (pSocket != nullptr) {
                    auto pHandle = pSocket->Binding();
                    if (pHandle != nullptr) {
                        Log()->Notice(_T("[%s:%d] API client disconnected."), pHandle->PeerIP(), pHandle->PeerPort());
                    }
                } else {
                    Log()->Notice(_T("API client disconnected."));
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            auto pConnection = dynamic_cast<CSMTPConnection *> (AConnection);
            auto pClient = dynamic_cast<CSMTPClient *> (pConnection->Client());

            CStringList SQL;

            const auto &session = pClient->Data()["session"];

            api::authorize(SQL, session);
            for (int i = 0; i < pClient->Messages().Count(); ++i) {
                const auto& Message = pClient->Messages()[i];
                api::set_object_label(SQL, Message.MessageId(), E.what());
                api::execute_object_action(SQL, Message.MessageId(), "fail");
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
            DebugNotify(AConnection, ANotify);

            if (m_Status == psRunning) {
                for (int i = 0; i < m_Sessions.Count(); ++i) {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    new CMessageHandler(this, m_Sessions[i], ANotify->extra, [this](auto &&Handler) { DoMessage(Handler); });
#else
                    new CMessageHandler(this, m_Sessions[i], ANotify->extra, std::bind(&CMessageServer::DoMessage, this, _1));
#endif
                }

                UnloadMessageQueue();
            } else {
                Log()->Error(APP_LOG_ALERT, 0, "Notify alert: Service not running.");
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

        void CMessageServer::DoPQClientException(CPQClient *AClient, const Delphi::Exception::Exception &E) {
            CServerProcess::DoPQClientException(AClient, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoPQConnectException(CPQConnection *AConnection, const Delphi::Exception::Exception &E) {
            CServerProcess::DoPQConnectException(AConnection, E);
            if (m_Status == psRunning) {
                DoError(E);
                m_Queue.Clear();
                m_FixedDate = Now() + (CDateTime) 3 / SecsPerDay;
            }
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
