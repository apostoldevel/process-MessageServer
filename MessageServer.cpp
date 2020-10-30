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

#define PROVIDER_APPLICATION_NAME "service_account"

extern "C++" {

namespace Apostol {

    namespace Processes {

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageServer ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CMessageServer::CMessageServer(CCustomProcess *AParent, CApplication *AApplication):
                inherited(AParent, AApplication, "message server") {

            m_FixedDate = Now();
            m_CheckDate = Now();

            m_HeartbeatInterval = 5;
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
                Log()->Error(APP_LOG_EMERG, 0, APP_FILE_NOT_FOUND, ConfigFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitSMTPConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config) {
            Config.Location() = IniFile.ReadString(Section, "host", "localhost:25");
            Config.UserName() = IniFile.ReadString(Section, "username", "smtp");
            Config.Password() = IniFile.ReadString(Section, "password", "smtp");
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

            pClient->OnRequest([this](auto && Sender) { DoRequest(Sender); });
            pClient->OnReply([this](auto && Sender) { DoReply(Sender); });
#else
            pClient->OnVerbose(std::bind(&CMessageServer::DoVerbose, this, _1, _2, _3, _4));
            pClient->OnAccessLog(std::bind(&CMessageServer::DoAccessLog, this, _1));
            pClient->OnException(std::bind(&CMessageServer::DoException, this, _1, _2));
            pClient->OnEventHandlerException(std::bind(&CMessageServer::DoServerEventHandlerException, this, _1, _2));
            pClient->OnConnected(std::bind(&CMessageServer::DoSMTPConnected, this, _1));
            pClient->OnDisconnected(std::bind(&CMessageServer::DoSMTPDisconnected, this, _1));
            pClient->OnNoCommandHandler(std::bind(&CMessageServer::DoNoCommandHandler, this, _1, _2, _3));

            pClient->OnRequest(std::bind(&CMessageServer::DoRequest, this, _1));
            pClient->OnReply(std::bind(&CMessageServer::DoReply, this, _1));
#endif

            return pClient;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::BeforeRun() {
            sigset_t set;

            Application()->Header(Application()->Name() + ": message server");

            Log()->Debug(0, MSG_PROCESS_START, GetProcessName(), Application()->Header().c_str());

            InitSignals();

            Config()->Reload();

            LoadSMTPConfig(Config()->IniFile().ReadString("process/MessageServer", "smtp", "conf/smtp.conf"));
            LoadConfig(Config()->IniFile().ReadString("worker/sba", "config", "conf/sba.conf"), m_Profiles, InitSBAConfig);

            LoadProviders(m_Providers);

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
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
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

                if (sig_reopen) {
                    sig_reopen = 0;
                    Log()->Error(APP_LOG_NOTICE, 0, "reopening logs");
                    //ReopenFiles(-1);
                }
            }

            Log()->Error(APP_LOG_NOTICE, 0, "stop message server");
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CMessageServer::DoExecute(CTCPConnection *AConnection) {
            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::AddAuthorize(CStringList &SQL, const CString& Username, const CString& Area) {
            SQL.Add(CString().Format("SELECT * FROM api.set_session('%s', '%s');", Username.c_str(), Area.c_str()));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::RunAction(CStringList &SQL, const CString &MsgId, const CString &Action) {
            SQL.Add(CString().Format("SELECT * FROM api.run_action(%s, %s);",
                                     MsgId.c_str(),
                                     PQQuoteLiteral(Action).c_str()
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

        void CMessageServer::RunAPI(CStringList &SQL, const CString &Path, const CJSON &Payload) {
            const auto &payload = Payload.IsNull() ? "null" : PQQuoteLiteral(Payload.ToString());
            SQL.Add(CString()
                .MaxFormatSize(256 + Path.Size() + payload.Size())
                .Format("SELECT * FROM rest.api('%s', %s::jsonb);",
                                    Path.c_str(),
                                    payload.c_str()
            ));
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CMessageServer::CreateServiceToken(const CProvider &Provider, const CString &Application) {

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

        void CMessageServer::FetchAccessToken(const CProvider &Provider) {

            auto OnRequestToken = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &token_uri = Sender->Data()["token_uri"];
                const auto &grant_type = Sender->Data()["grant_type"];
                const auto &assertion = Sender->Data()["assertion"];

                ARequest->Content = _T("grant_type=");
                ARequest->Content << CHTTPServer::URLEncode(grant_type);

                ARequest->Content << _T("&assertion=");
                ARequest->Content << CHTTPServer::URLEncode(assertion);

                CHTTPRequest::Prepare(ARequest, _T("POST"), token_uri.c_str(), _T("application/x-www-form-urlencoded"));

                DebugRequest(ARequest);
            };

            auto OnReplyToken = [this](CTCPConnection *Sender) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pReply = pConnection->Reply();

                DebugReply(pReply);

                const CJSON Json(pReply->Content);

                m_AccessToken = Json["access_token"].AsString();

                return true;
            };

            auto OnException = [](CTCPConnection *Sender, const Delphi::Exception::Exception &E) {

                auto pConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                DebugReply(pConnection->Reply());

                Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            CLocation URI("https://oauth2.googleapis.com/token");

            auto pClient = GetClient(URI.hostname, URI.port);

            pClient->Data().Values("token_uri", URI.pathname);
            pClient->Data().Values("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            pClient->Data().Values("assertion", m_ServiceToken);

            pClient->OnRequest(OnRequestToken);
            pClient->OnExecute(OnReplyToken);
            pClient->OnException(OnException);

            pClient->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::FetchCerts(CProvider &Provider) {

            const auto& URI = Provider.CertURI(PROVIDER_APPLICATION_NAME);

            if (URI.IsEmpty()) {
                Log()->Error(APP_LOG_INFO, 0, _T("Certificate URI in provider \"%s\" is empty."), Provider.Name.c_str());
                return;
            }

            Log()->Error(APP_LOG_INFO, 0, _T("Trying to fetch public keys from: %s"), URI.c_str());

            auto OnRequest = [&Provider](CHTTPClient *Sender, CHTTPRequest *ARequest) {
                const auto& client_x509_cert_url = std::string(Provider.Params[PROVIDER_APPLICATION_NAME]["client_x509_cert_url"].AsString());

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

                    m_ServiceToken = CreateServiceToken(Provider, PROVIDER_APPLICATION_NAME);

                    FetchAccessToken(Provider);
                } catch (Delphi::Exception::Exception &E) {
                    Provider.KeyStatus = CProvider::ksFailed;
                    Log()->Error(APP_LOG_EMERG, 0, "[Certificate] Message: %s", E.what());
                }

                pConnection->CloseConnection(true);
                return true;
            };

            auto OnException = [&Provider](CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
                auto pConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
                auto pClient = dynamic_cast<CHTTPClient *> (pConnection->Client());

                Provider.KeyStatusTime = Now();
                Provider.KeyStatus = CProvider::ksFailed;

                Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
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
            auto& Provider = m_Providers["firebase"].Value();
            if (Provider.ApplicationExists(PROVIDER_APPLICATION_NAME)) {
                if (Provider.KeyStatus == CProvider::ksUnknown) {
                    FetchCerts(Provider);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckProviders() {
            auto& Provider = m_Providers["firebase"].Value();
            if (Provider.ApplicationExists(PROVIDER_APPLICATION_NAME)) {
                if (Provider.KeyStatus != CProvider::ksUnknown) {
                    Provider.KeyStatusTime = Now();
                    Provider.KeyStatus = CProvider::ksUnknown;
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendSMTP(const CPQueryResult &Messages) {

            CSMTPClient *pSMTPClient = nullptr;

            if (Messages.Count() > 0 ) {

                CString Temp;

                for (int Row = 0; Row < Messages.Count(); Row++) {

                    const auto &Record = Messages[Row];

                    const auto &MsgId = Record.Values("id");

                    if (m_MailManager.InProgress(MsgId))
                        continue;

                    const auto &profile = Record.Values("profile");

                    const auto pos = profile.Find('@');
                    const auto &Profile = pos == CString::npos ? profile : profile.SubString(0, pos);

                    const auto &From = m_Configs[Profile].Value().UserName();
                    const auto &To = Record.Values("address");
                    const auto &Subject = Record.Values("subject");
                    const auto &Body = Record.Values("content");

                    if (Temp.IsEmpty())
                        Temp = profile;

                    if (Temp != profile) {
                        Temp = profile;
                        pSMTPClient->SendMail();
                        pSMTPClient = nullptr;
                    }

                    if (pSMTPClient == nullptr) {
                        pSMTPClient = GetSMTPClient(m_Configs[Profile].Value());
                    }

                    auto &Message = pSMTPClient->NewMessage();

                    Message.MsgId() = MsgId;
                    Message.From() = From;
                    Message.To() = To;
                    Message.Subject() = Subject;
                    Message.Body() = Body;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    Message.OnDone([this](auto &&Message) { DoDone(Message); });
                    Message.OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
                    Message.OnDone(std::bind(&CMessageServer::DoDone, this, _1));
                    Message.OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
                }

                if (pSMTPClient != nullptr)
                    pSMTPClient->SendMail();
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

        void CMessageServer::SendFCM(const CPQueryResult &Messages) {

            auto OnRequest = [this](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/json"));

                ARequest->AddHeader("Authorization", CString().Format("Bearer %s", m_AccessToken.c_str()).c_str());

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

                Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            if (m_AccessToken.IsEmpty())
                return;

            if (Messages.Count() > 0 ) {

                for (int Row = 0; Row < Messages.Count(); Row++) {

                    const auto &Record = Messages[Row];

                    const auto &MsgId = Record.Values("id");

                    if (InProgress(MsgId))
                        continue;

                    const auto &Profile = Record.Values("profile");
                    const auto &Address = Record.Values("address");
                    const auto &Subject = Record.Values("subject");
                    const auto &Content = Record.Values("content");

                    auto pMessage = new CMessage();

                    pMessage->MsgId() = MsgId;
                    pMessage->From() = Profile;
                    pMessage->To() = Address;
                    pMessage->Subject() = Subject;
                    pMessage->Content() = Content;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    pMessage->OnDone([this](auto &&Message) { DoDone(Message); });
                    pMessage->OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
                    pMessage->OnDone(std::bind(&CMessageServer::DoDone, this, _1));
                    pMessage->OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
                    CLocation URI(CString().Format("https://fcm.googleapis.com/v1/projects/%s/messages:send", Profile.c_str()));

                    auto pClient = GetClient(URI.hostname, URI.port);

                    pClient->Data().Values("uri", URI.pathname);

                    pClient->Data().AddObject("message", pMessage);

                    pClient->OnRequest(OnRequest);
                    pClient->OnExecute(OnExecute);
                    pClient->OnException(OnException);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    pClient->OnConnected([this](auto &&Sender) { DoAPIConnected(Sender); });
                    pClient->OnDisconnected([this](auto &&Sender) { DoAPIDisconnected(Sender); });
#else
                    pClient->OnConnected(std::bind(&CMessageServer::DoFCMConnected, this, _1));
                    pClient->OnDisconnected(std::bind(&CMessageServer::DoFCMDisconnected, this, _1));
#endif
                    pClient->Active(true);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::SendSBA(const CPQueryResult &Messages) {

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
                    const auto& Json = CJSON(pReply->Content);

                    const auto& Agent = pClient->Data()["agent"];
                    const auto& Area = pClient->Data()["area"];

                    CStringList SQL;

                    AddAuthorize(SQL, "apibot", Area);

                    CJSON Message;

                    Message.Object().AddPair("parent", pMessage->MsgId());
                    Message.Object().AddPair("type", "message.inbox");
                    Message.Object().AddPair("agent", Agent);
                    Message.Object().AddPair("profile", pMessage->From());
                    Message.Object().AddPair("address", pMessage->To().First());
                    Message.Object().AddPair("subject", pMessage->Subject());
                    Message.Object().AddPair("content", Json.ToString());

                    RunAPI(SQL, "/message/set", Message);

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

                Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pClient->Host().c_str(), pClient->Port(), E.what());
            };

            if (Messages.Count() > 0 ) {

                for (int Row = 0; Row < Messages.Count(); Row++) {

                    const auto &Record = Messages[Row];

                    const auto &MsgId = Record.Values("id");

                    if (InProgress(MsgId))
                        continue;

                    const auto &Agent = Record.Values("agentcode");
                    const auto &Area = Record.Values("areacode");

                    const auto &Profile = Record.Values("profile");
                    const auto &Address = Record.Values("address");
                    const auto &Subject = Record.Values("subject");
                    const auto &Content = Record.Values("content");

                    auto pMessage = new CMessage();

                    pMessage->MsgId() = MsgId;
                    pMessage->From() = Profile;
                    pMessage->To() = Address;
                    pMessage->Subject() = Subject;
                    pMessage->Content() = Content;

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    pMessage->OnDone([this](auto &&Message) { DoDone(Message); });
                    pMessage->OnFail([this](auto &&Message, auto &&Error) { DoFail(Message, Error); });
#else
                    pMessage->OnDone(std::bind(&CMessageServer::DoDone, this, _1));
                    pMessage->OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
                    const auto& uri = m_Profiles[Profile].Value()["uri"] + (Address.front() == '/' ? Address : '/' + Address);
                    const auto& userName = m_Profiles[Profile].Value()["username"];
                    const auto& password = m_Profiles[Profile].Value()["password"];

                    CLocation URI(uri);

                    auto pClient = GetClient(URI.hostname, URI.port);

                    pClient->Data().Values("uri", URI.pathname);
                    pClient->Data().Values("username", userName);
                    pClient->Data().Values("password", password);

                    pClient->Data().Values("agent", Agent);
                    pClient->Data().Values("area", Area);

                    pClient->Data().AddObject("message", pMessage);

                    pClient->OnRequest(OnRequest);
                    pClient->OnExecute(OnExecute);
                    pClient->OnException(OnException);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    pClient->OnConnected([this](auto &&Sender) { DoAPIConnected(Sender); });
                    pClient->OnDisconnected([this](auto &&Sender) { DoAPIDisconnected(Sender); });
#else
                    pClient->OnConnected(std::bind(&CMessageServer::DoFCMConnected, this, _1));
                    pClient->OnDisconnected(std::bind(&CMessageServer::DoFCMDisconnected, this, _1));
#endif
                    pClient->Active(true);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckMessage() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults Result;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, Result);
                    // Skip Result[0] - api.set_session
                    SendSMTP(Result[1]);
                    SendFCM(Result[2]);
                    SendSBA(Result[3]);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            CStringList SQL;

            AddAuthorize(SQL);

            SQL.Add("SELECT * FROM api.message('message.outbox', 'smtp.agent', 'prepared') ORDER BY created LIMIT 10;");
            SQL.Add("SELECT * FROM api.message('message.outbox', 'fcm.agent', 'prepared') ORDER BY created LIMIT 10;");
            SQL.Add("SELECT * FROM api.message('message.outbox', 'sba.agent', 'prepared') ORDER BY created LIMIT 10;");

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoError(const Delphi::Exception::Exception &E) {
            m_CheckDate = Now() + (CDateTime) 30 / SecsPerDay;
            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoHeartbeat() {
            auto now = Now();

            if ((now >= m_FixedDate)) {
                m_FixedDate = now + (CDateTime) 55 * 60 / SecsPerDay; // 55 min

                CheckProviders();
                FetchProviders();
            }

            if ((now >= m_CheckDate)) {
                CheckMessage();
                m_CheckDate = now + (CDateTime) m_HeartbeatInterval / SecsPerDay;

                m_MailManager.CleanUp();
            }

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

            AddAuthorize(SQL);
            RunAction(SQL, Message.MsgId(), "send");

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

            AddAuthorize(SQL);
            RunAction(SQL, Message.MsgId(), "cancel");
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

            AddAuthorize(SQL);
            RunAction(SQL, Message.MsgId(), "done");
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

            AddAuthorize(SQL);
            RunAction(SQL, Message.MsgId(), "fail");
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
            if (pConnection != nullptr) {
                auto pClient = dynamic_cast<CSMTPClient *> (pConnection->Client());
                for (int i = 0; i < pClient->Messages().Count(); ++i)
                    DoSend(pClient->Messages()[i]);

                Log()->Message(_T("[%s:%d] SMTP client connected."), pConnection->Socket()->Binding()->PeerIP(),
                               pConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoSMTPDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            if (pConnection != nullptr) {
                if (!pConnection->ClosedGracefully()) {
                    Log()->Message(_T("[%s:%d] FCM client disconnected."), pConnection->Socket()->Binding()->PeerIP(),
                                   pConnection->Socket()->Binding()->PeerPort());
                } else {
                    Log()->Message(_T("FCM client disconnected."));
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

        void CMessageServer::DoRequest(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            const auto& LCommand = pConnection->Command();
            CMemoryStream Stream;
            LCommand.ToBuffers(&Stream);
            CString S;
            S.LoadFromStream(&Stream);
            DebugMessage("C: %s", S.c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoReply(CObject *Sender) {
            auto pConnection = dynamic_cast<CSMTPConnection *>(Sender);
            const auto& LCommand = pConnection->Command();
            DebugMessage("S: %s", LCommand.Reply().Text().c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            auto pConnection = dynamic_cast<CSMTPConnection *> (AConnection);
            auto pClient = dynamic_cast<CSMTPClient *> (pConnection->Client());

            CStringList SQL;

            AddAuthorize(SQL);
            for (int i = 0; i < pClient->Messages().Count(); ++i) {
                const auto& Message = pClient->Messages()[i];
                SetObjectLabel(SQL, Message.MsgId(), E.what());
            }

            m_CheckDate = Now() + (CDateTime) 10 / SecsPerDay;

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        CPQPollQuery *CMessageServer::GetQuery(CPollConnection *AConnection) {
            auto LQuery = CServerProcess::GetQuery(AConnection);

            if (Assigned(LQuery)) {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                LQuery->OnPollExecuted([this](auto && APollQuery) { DoPostgresQueryExecuted(APollQuery); });
                LQuery->OnException([this](auto && APollQuery, auto && AException) { DoPostgresQueryException(APollQuery, AException); });
#else
                LQuery->OnPollExecuted(std::bind(&CMessageServer::DoPostgresQueryExecuted, this, _1));
                LQuery->OnException(std::bind(&CMessageServer::DoPostgresQueryException, this, _1, _2));
#endif
            }

            return LQuery;
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
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}

}
