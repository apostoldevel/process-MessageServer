/*++

Program name:

  Apostol Web Service

Module Name:

  MessageServer.hpp

Notices:

  Process: Message Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_PROCESS_MESSAGE_SERVER_HPP
#define APOSTOL_PROCESS_MESSAGE_SERVER_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Processes {

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageServer --------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        typedef TPairs<CSMTPConfig> CSMTPConfigs;
        //--------------------------------------------------------------------------------------------------------------

        class CMessageServer: public CProcessCustom {
            typedef CProcessCustom inherited;

        private:

            CProcessStatus m_Status;

            CString m_ClientId;
            CString m_ClientSecret;

            CString m_Session;
            CString m_Secret;

            CString m_ApiBot;
            CString m_MailBot;

            CString m_Agent;
            CString m_Host;

            CProviders m_Providers;

            CSMTPConfigs m_Configs;

            CDateTime m_AuthDate;
            CDateTime m_FixedDate;
            CDateTime m_CheckDate;

            CSMTPManager m_MailManager;

            CStringListPairs m_Tokens;

            TPairs<CStringListPairs> m_Profiles;

            void BeforeRun() override;
            void AfterRun() override;

            void Authentication();
            void CheckListen();
            void InitListen();

            bool InProgress(const CString &MsgId);

            void FetchCerts(CProvider &Provider, const CString &Application);

            void FetchProviders();
            void CheckProviders();

            void CheckOutbox();
            void CheckMessages(const CPQueryResult& Messages);

            void SendSMTP(const CStringPairs &Record);
            void SendAPI(const CStringPairs &Record, const CStringListPairs &Config);
            void SendFCM(const CStringPairs &Record, const CStringListPairs &Config);
            void SendM2M(const CStringPairs &Record, const CStringListPairs &Config);
            void SendSBA(const CStringPairs &Record, const CStringListPairs &Config);

            void CreateAccessToken(const CProvider &Provider, const CString &Application, CStringList &Tokens);

            static CString CreateToken(const CProvider& Provider, const CString &Application);
            static CString CreateGoogleToken(const CProvider& Provider, const CString &Application);

            static void LoadSMTPConfig(const CString &FileName, CSMTPConfigs &Configs);
            CSMTPClient *GetSMTPClient(const CSMTPConfig &Config);

            static void InitSMTPConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config);
            static void InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);

        protected:

            void DoTimer(CPollEventHandler *AHandler) override;

            void DoHeartbeat();
            void DoError(const Delphi::Exception::Exception &E);

            void DoSend(const CMessage &Message);
            void DoDone(const CMessage &Message);

            void DoCancel(const CMessage &Message, const CString &Error);
            void DoFail(const CMessage &Message, const CString &Error);

            void DoSMTPRequest(CObject *Sender);
            void DoSMTPReply(CObject *Sender);

            void DoSMTPConnected(CObject *Sender);
            void DoSMTPDisconnected(CObject *Sender);

            void DoAPIConnected(CObject *Sender);
            void DoAPIDisconnected(CObject *Sender);

            void DoException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E);
            bool DoExecute(CTCPConnection *AConnection) override;

            void DoPostgresNotify(CPQConnection *AConnection, PGnotify *ANotify);

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery);
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

        public:

            explicit CMessageServer(CCustomProcess* AParent, CApplication *AApplication);

            ~CMessageServer() override = default;

            static class CMessageServer *CreateProcess(CCustomProcess *AParent, CApplication *AApplication) {
                return new CMessageServer(AParent, AApplication);
            }

            void Run() override;
            void Reload() override;
        };
        //--------------------------------------------------------------------------------------------------------------

    }
}

using namespace Apostol::Processes;
}
#endif //APOSTOL_PROCESS_MESSAGE_SERVER_HPP
