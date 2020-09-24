/*++

Program name:

  Apostol Web Service

Module Name:

  MessageServer.cpp

Notices:

  Proccess: Mail Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#include "Core.hpp"
#include "MessageServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Processes {

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageServer ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CMessageServer::CMessageServer(CCustomProcess *AParent, CApplication *AApplication):
                inherited(AParent, AApplication, "message server") {
            m_CheckDate = Now();
            m_HeartbeatInterval = 5;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::LoadConfig(CSMTPConfig &Value) {
            Value.Location() = Config()->IniFile().ReadString("smtp", "host", "localhost:25");
            Value.UserName() = Config()->IniFile().ReadString("smtp", "username", "smtp");
            Value.Password() = Config()->IniFile().ReadString("smtp", "password", "smtp");
            Value.Domain() = Config()->IniFile().ReadString("smtp", "domain", "apostol-web-service.ru");
        }
        //--------------------------------------------------------------------------------------------------------------

        CSMTPClient *CMessageServer::GetSMTPClient(const CSMTPConfig &Config) {

            auto LCLient = m_ClientManager.Add(Config);

            LCLient->PollStack(PQServer().PollStack());

            LCLient->ClientName() = Application()->Title();

            LCLient->AutoConnect(true);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            LCLient->OnVerbose([this](auto && Sender, auto && AConnection, auto && AFormat, auto && args) { DoVerbose(Sender, AConnection, AFormat, args); });
            LCLient->OnAccessLog([this](auto && AConnection) { DoAccessLog(AConnection); });
            LCLient->OnException([this](auto && AConnection, auto && AException) { DoException(AConnection, AException); });
            LCLient->OnEventHandlerException([this](auto && AHandler, auto && AException) { DoServerEventHandlerException(AHandler, AException); });
            LCLient->OnDisconnected([this](auto && Sender) { DoDisconnected(Sender); });
            LCLient->OnConnected([this](auto && Sender) { DoConnected(Sender); });
            LCLient->OnDisconnected([this](auto && Sender) { DoDisconnected(Sender); });
            LCLient->OnNoCommandHandler([this](auto && Sender, auto && AData, auto && AConnection) { DoNoCommandHandler(Sender, AData, AConnection); });

            LCLient->OnRequest([this](auto && Sender) { DoRequest(Sender); });
            LCLient->OnReply([this](auto && Sender) { DoReply(Sender); });
#else
            LCLient->OnVerbose(std::bind(&CMessageServer::DoVerbose, this, _1, _2, _3, _4));
            LCLient->OnAccessLog(std::bind(&CMessageServer::DoAccessLog, this, _1));
            LCLient->OnException(std::bind(&CMessageServer::DoException, this, _1, _2));
            LCLient->OnEventHandlerException(std::bind(&CMessageServer::DoServerEventHandlerException, this, _1, _2));
            LCLient->OnConnected(std::bind(&CMessageServer::DoConnected, this, _1));
            LCLient->OnDisconnected(std::bind(&CMessageServer::DoDisconnected, this, _1));
            LCLient->OnNoCommandHandler(std::bind(&CMessageServer::DoNoCommandHandler, this, _1, _2, _3));

            LCLient->OnRequest(std::bind(&CMessageServer::DoRequest, this, _1));
            LCLient->OnReply(std::bind(&CMessageServer::DoReply, this, _1));
#endif

            return LCLient;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::BeforeRun() {
            sigset_t set;

            Application()->Header(Application()->Name() + ": message server");

            Log()->Debug(0, MSG_PROCESS_START, GetProcessName(), Application()->Header().c_str());

            InitSignals();

            Config()->Reload();

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

        void CMessageServer::AddAuthorize(CStringList &SQL) const {
            SQL.Add(CString().Format("SELECT * FROM api.authorize(%s, %s, %s, %s);",
                                     PQQuoteLiteral(m_Auth.Session).c_str(),
                                     PQQuoteLiteral(m_Auth.Secret).c_str(),
                                     PQQuoteLiteral(m_Auth.Agent).c_str(),
                                     PQQuoteLiteral(m_Auth.Host).c_str()
            ));

            SQL.Add(CString().Format("SELECT * FROM api.su('mailbot', %s);",
                                     PQQuoteLiteral(m_Auth.Password).c_str()
            ));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitServer() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQResult *Result;
                CStringList SQL;

                try {
                    for (int I = 0; I < APollQuery->Count(); I++) {
                        Result = APollQuery->Results(I);

                        if (Result->ExecStatus() != PGRES_TUPLES_OK)
                            throw Delphi::Exception::EDBError(Result->GetErrorMessage());

                        if (I == 0) {
                            m_Auth.Session = Result->GetValue(0, 0);
                            m_Auth.Secret = Result->GetValue(0, 1);
                            m_Auth.Code = Result->GetValue(0, 2);

                            m_CheckDate = Now();
                        }
                    }
                } catch (Delphi::Exception::Exception &E) {
                    m_CheckDate = Now() + (CDateTime) 60 / SecsPerDay;
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                m_CheckDate = Now() + (CDateTime) 60 / SecsPerDay;
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            };

            const auto &ConnInfo = Config()->PostgresConnInfo()["helper"].Value();

            m_Auth.Username = ConnInfo["user"];
            m_Auth.Password = ConnInfo["password"];

            m_Auth.Agent = "Message Server";

            CString LHost;
            LHost.SetLength(NI_MAXHOST);
            if (GStack->GetHostName(LHost.Data(), LHost.Size())) {
                LHost.Truncate();
                if (!LHost.IsEmpty()) {
                    m_Auth.Host.SetLength(16);
                    GStack->GetIPByName(LHost.c_str(), m_Auth.Host.Data(), m_Auth.Host.Size());
                }
            } else {
                m_Auth.Host = _T("127.0.0.1");
            }

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM api.login(%s, %s, %s, %s);",
                    PQQuoteLiteral(m_Auth.Username).c_str(),
                    PQQuoteLiteral(m_Auth.Password).c_str(),
                    PQQuoteLiteral(m_Auth.Agent).c_str(),
                    PQQuoteLiteral(m_Auth.Host).c_str()
            ));

            SQL.Add(CString().Format("SELECT * FROM api.su('mailbot', %s);",
                    PQQuoteLiteral(m_Auth.Password).c_str()
            ));

            ExecSQL(SQL, nullptr, OnExecuted, OnException);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckMessage() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults Result;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, Result);

                    const auto &Authenticate = Result[0];
                    if (Authenticate[0].Values("authorized") != "t") {
                        m_Auth.Clear();
                        return;
                    }

                    const auto &Messages = Result[2]; // Skip api.su

                    if (Messages.Count() > 0 ) {

                        AddAuthorize(SQL);

                        CSMTPConfig LConfig;
                        LoadConfig(LConfig);

                        auto LSMTPClient = GetSMTPClient(LConfig);

                        for (int Row = 0; Row < Messages.Count(); Row++) {

                            const auto &Record = Messages[Row];

                            const auto& MsgId = Record.Values("id");

                            if (m_ClientManager.InProgress(MsgId))
                                continue;

                            auto &LMessage = LSMTPClient->NewMessage();

                            const auto &from = Record.Values("addressfrom");
                            const auto &to = Record.Values("addressto");

                            LMessage.MsgId() = MsgId;
                            LMessage.MessageId() = CString().Format("<%s@%s>", Record.Values("code").c_str(), LConfig.Domain().c_str());
                            LMessage.From() = from;
                            LMessage.To() = to;
                            LMessage.Subject() = Record.Values("subject");

                            LMessage.Body().Add("MIME-Version: 1.0" );

                            CString LDate;
                            LDate.SetLength(64);
                            if (CHTTPReply::GetGMT(LDate.Data(), LDate.Size()) != nullptr) {
                                LDate.Truncate();
                                LMessage.Body().Add("Date: " + LDate);
                            }

                            LMessage.Body().Add("Message-ID: " + LMessage.MessageId());
                            LMessage.Body().Add("From: " + from);
                            LMessage.Body().Add("To: " + to);
                            LMessage.Body().Add("Subject: " + LMessage.Subject());
                            LMessage.Body().Add("Content-Type: text/html; charset=UTF8");
                            LMessage.Body().Add("Content-Transfer-Encoding: BASE64");
                            LMessage.Body().Add(""); /* empty line to divide headers from body, see RFC5322 */

                            LMessage.Body() << base64_encode(Record.Values("body"));

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                            LMessage.OnDone([this](auto && Message) { DoDone(Message); });
                            LMessage.OnFail([this](auto && Message) { DoFail(Message); });
#else
                            LMessage.OnDone(std::bind(&CMessageServer::DoDone, this, _1));
                            LMessage.OnFail(std::bind(&CMessageServer::DoFail, this, _1));
#endif
                            SQL.Add(CString().Format("SELECT * FROM api.run_action(%s, 'send');", LMessage.MsgId().c_str()));
                        }

                        try {
                            ExecSQL(SQL);
                            LSMTPClient->SendMail();
                        } catch (Delphi::Exception::Exception &E) {
                            Log()->Error(APP_LOG_EMERG, 0, E.what());
                        }
                    }
                } catch (Delphi::Exception::Exception &E) {
                    m_CheckDate = Now() + (CDateTime) 60 / SecsPerDay;
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                m_CheckDate = Now() + (CDateTime) 60 / SecsPerDay;
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            };

            CStringList SQL;

            AddAuthorize(SQL);
            SQL.Add("SELECT * FROM api.message('outbox', 'smtp', 'prepared') ORDER BY created LIMIT 10;");

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoHeartbeat() {
            auto now = Now();
            try {
                if ((now >= m_CheckDate)) {
                    if (m_Auth.Session.IsEmpty()) {
                        InitServer();
                    } else {
                        CheckMessage();
                    }

                    m_CheckDate = now + (CDateTime) m_HeartbeatInterval / SecsPerDay;

                    m_ClientManager.CleanUp();
                }
            } catch (Delphi::Exception::Exception &E) {
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoTimer(CPollEventHandler *AHandler) {
            uint64_t exp;

            auto LTimer = dynamic_cast<CEPollTimer *> (AHandler->Binding());
            LTimer->Read(&exp, sizeof(uint64_t));

            try {
                DoHeartbeat();
            } catch (Delphi::Exception::Exception &E) {
                DoServerEventHandlerException(AHandler, E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoDone(CSMTPMessage *AMessage) {
            CStringList SQL;

            AddAuthorize(SQL);
            SQL.Add(CString().Format("SELECT * FROM api.run_action(%s, 'done');", AMessage->MsgId().c_str()));

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }

            Log()->Error(APP_LOG_NOTICE, 0, "[%s] Message sent.", AMessage->MessageId().c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoFail(CSMTPMessage *AMessage) {
            CStringList SQL;

            AddAuthorize(SQL);
            SQL.Add(CString().Format("SELECT * FROM api.run_action(%s, 'fail');", AMessage->MsgId().c_str()));

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }

            Log()->Error(APP_LOG_EMERG, 0, "[%s] Message not sent.", AMessage->MessageId().c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoRequest(CObject *Sender) {
            auto LConnection = dynamic_cast<CSMTPConnection *>(Sender);
            const auto& LCommand = LConnection->Command();
            CMemoryStream Stream;
            LCommand.ToBuffers(&Stream);
            CString S;
            S.LoadFromStream(&Stream);
            DebugMessage("C: %s", S.c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoReply(CObject *Sender) {
            auto LConnection = dynamic_cast<CSMTPConnection *>(Sender);
            const auto& LCommand = LConnection->Command();
            for (int i = 0; i < LCommand.Reply().Count(); ++i)
              DebugMessage("S: %s\n", LCommand.Reply()[i].c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoConnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CSMTPConnection *>(Sender);
            if (LConnection != nullptr) {
                Log()->Message(_T("[%s:%d] Mail client connected."), LConnection->Socket()->Binding()->PeerIP(),
                               LConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoDisconnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CSMTPConnection *>(Sender);
            if (LConnection != nullptr) {
                if (!LConnection->ClosedGracefully()) {
                    Log()->Message(_T("[%s:%d] Mail client disconnected."), LConnection->Socket()->Binding()->PeerIP(),
                                   LConnection->Socket()->Binding()->PeerPort());
                } else {
                    Log()->Message(_T("Mail client disconnected."));
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            Log()->Error(APP_LOG_EMERG, 0, E.what());
            sig_reopen = 1;
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
            CPQResult *Result;

            try {
                for (int I = 0; I < APollQuery->Count(); I++) {
                    Result = APollQuery->Results(I);

                    if (Result->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(Result->GetErrorMessage());
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
