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
                    InitConfig(IniFile, Section, Config);
                }

                auto& defaultConfig = m_Configs.Default();
                if (defaultConfig.Name().IsEmpty()) {
                    defaultConfig.Name() = _T("default");
                    auto& Config = defaultConfig.Value();
                    InitConfig(IniFile, defaultConfig.Name(), Config);
                }
            } else {
                Log()->Error(APP_LOG_EMERG, 0, APP_FILE_NOT_FOUND, ConfigFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::InitConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config) {
            Config.Location() = IniFile.ReadString(Section, "host", "localhost:25");
            Config.UserName() = IniFile.ReadString(Section, "username", "smtp");
            Config.Password() = IniFile.ReadString(Section, "password", "smtp");
        }
        //--------------------------------------------------------------------------------------------------------------

        CSMTPClient *CMessageServer::GetSMTPClient(const CSMTPConfig &Config) {

            auto pClient = m_ClientManager.Add(Config);

            pClient->PollStack(PQServer().PollStack());

            pClient->ClientName() = Application()->Title();

            pClient->AutoConnect(true);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pClient->OnVerbose([this](auto && Sender, auto && AConnection, auto && AFormat, auto && args) { DoVerbose(Sender, AConnection, AFormat, args); });
            pClient->OnAccessLog([this](auto && AConnection) { DoAccessLog(AConnection); });
            pClient->OnException([this](auto && AConnection, auto && AException) { DoException(AConnection, AException); });
            pClient->OnEventHandlerException([this](auto && AHandler, auto && AException) { DoServerEventHandlerException(AHandler, AException); });
            pClient->OnDisconnected([this](auto && Sender) { DoDisconnected(Sender); });
            pClient->OnConnected([this](auto && Sender) { DoConnected(Sender); });
            pClient->OnDisconnected([this](auto && Sender) { DoDisconnected(Sender); });
            pClient->OnNoCommandHandler([this](auto && Sender, auto && AData, auto && AConnection) { DoNoCommandHandler(Sender, AData, AConnection); });

            pClient->OnRequest([this](auto && Sender) { DoRequest(Sender); });
            pClient->OnReply([this](auto && Sender) { DoReply(Sender); });
#else
            pClient->OnVerbose(std::bind(&CMessageServer::DoVerbose, this, _1, _2, _3, _4));
            pClient->OnAccessLog(std::bind(&CMessageServer::DoAccessLog, this, _1));
            pClient->OnException(std::bind(&CMessageServer::DoException, this, _1, _2));
            pClient->OnEventHandlerException(std::bind(&CMessageServer::DoServerEventHandlerException, this, _1, _2));
            pClient->OnConnected(std::bind(&CMessageServer::DoConnected, this, _1));
            pClient->OnDisconnected(std::bind(&CMessageServer::DoDisconnected, this, _1));
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

        void CMessageServer::AddAuthorize(CStringList &SQL) {
            SQL.Add("SELECT * FROM api.set_session('mailbot', 'root');");
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

        void CMessageServer::AddMIME(const CString &MsgId, const CString &From, const CString &To, const CString &Subject,
                                     const CString &Body, CSMTPMessage &Message) {
            Message.MsgId() = MsgId;
            Message.From() = From;
            Message.To() = To;
            Message.Subject() = Subject;

            Message.Body().Add("MIME-Version: 1.0" );

            CString LDate;
            LDate.SetLength(64);
            if (CHTTPReply::GetGMT(LDate.Data(), LDate.Size()) != nullptr) {
                LDate.Truncate();
                Message.Body().Add("Date: " + LDate);
            }

            Message.Body().Add("From: " + From);
            Message.Body().Add("To: " + To);
            Message.Body().Add("Subject: " + CSMTPMessage::EncodingSubject(Subject)); /* Non-ASCII Text, see RFC 1342 */
            Message.Body().Add("Content-Type: text/html; charset=UTF8");
            Message.Body().Add("Content-Transfer-Encoding: BASE64");
            Message.Body().Add(""); /* empty line to divide headers from body, see RFC 5322 */

            Message.Body() << CSMTPMessage::SplitText(base64_encode(Body));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::CheckMessage() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults Result;
                CStringList SQL;

                CSMTPClient *pSMTPClient = nullptr;

                try {
                    CApostolModule::QueryToResults(APollQuery, Result);

                    const auto &Messages = Result[1]; // Skip api.set_session

                    if (Messages.Count() > 0 ) {

                        CString Temp;

                        for (int Row = 0; Row < Messages.Count(); Row++) {

                            const auto &Record = Messages[Row];

                            const auto& MsgId = Record.Values("id");

                            if (m_ClientManager.InProgress(MsgId))
                                continue;

                            const auto &addressFrom = Record.Values("addressfrom");

                            const auto Pos = addressFrom.Find('@');
                            const auto &Profile = Pos == CString::npos ? addressFrom : addressFrom.SubString(0, Pos);

                            const auto &From = m_Configs[Profile].Value().UserName();
                            const auto &To = Record.Values("addressto");
                            const auto &Subject = Record.Values("subject");
                            const auto &Body = Record.Values("body");

                            if (Temp.IsEmpty())
                                Temp = addressFrom;

                            if (Temp != addressFrom) {
                                Temp = addressFrom;
                                pSMTPClient->SendMail();
                                pSMTPClient = nullptr;
                            }

                            if (pSMTPClient == nullptr) {
                                pSMTPClient = GetSMTPClient(m_Configs[Profile].Value());
                            }

                            auto &LMessage = pSMTPClient->NewMessage();

                            LMessage.MsgId() = MsgId;
                            LMessage.From() = From;
                            LMessage.To() = To;
                            LMessage.Subject() = Subject;
                            LMessage.Body() = Body;

                            //AddMIME(MsgId, From, To, Subject, Body, LMessage);

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                            LMessage.OnDone([this](auto && Message) { DoDone(Message); });
                            LMessage.OnFail([this](auto && Message, auto && Error) { DoFail(Message, Error); });
#else
                            LMessage.OnDone(std::bind(&CMessageServer::DoDone, this, _1));
                            LMessage.OnFail(std::bind(&CMessageServer::DoFail, this, _1, _2));
#endif
                        }

                        if (pSMTPClient != nullptr)
                            pSMTPClient->SendMail();
                    }
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

            if ((now >= m_CheckDate)) {
                CheckMessage();
                m_CheckDate = now + (CDateTime) m_HeartbeatInterval / SecsPerDay;

                m_ClientManager.CleanUp();
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

        void CMessageServer::DoSend(const CSMTPMessage &Message) {
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

        void CMessageServer::DoCancel(const CSMTPMessage &Message, const CString &Error) {
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

        void CMessageServer::DoDone(const CSMTPMessage &Message) {
            CStringList SQL;

            AddAuthorize(SQL);
            RunAction(SQL, Message.MsgId(), "done");
            SetObjectLabel(SQL, Message.MsgId(), Message.MessageId());

            Log()->Message("[%s] Message sent successfully.", Message.MsgId().c_str());

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoFail(const CSMTPMessage &Message, const CString &Error) {
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

        void CMessageServer::DoConnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CSMTPConnection *>(Sender);
            if (LConnection != nullptr) {
                auto LClient = dynamic_cast<CSMTPClient *> (LConnection->Client());
                for (int i = 0; i < LClient->Messages().Count(); ++i)
                    DoSend(LClient->Messages()[i]);

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
            DebugMessage("S: %s", LCommand.Reply().Text().c_str());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CMessageServer::DoException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            auto LConnection = dynamic_cast<CSMTPConnection *> (AConnection);
            auto LClient = dynamic_cast<CSMTPClient *> (LConnection->Client());

            CStringList SQL;

            AddAuthorize(SQL);
            for (int i = 0; i < LClient->Messages().Count(); ++i) {
                const auto& Message = LClient->Messages()[i];
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
