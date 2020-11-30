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

            CString m_ClientId;
            CString m_ClientSecret;

            CString m_Session;
            CString m_Secret;

            CString m_Agent;
            CString m_Host;

            CProviders m_Providers;

            CSMTPConfigs m_Configs;

            int m_HeartbeatInterval;

            CDateTime m_AuthDate;
            CDateTime m_FixedDate;
            CDateTime m_CheckDate;

            CSMTPManager m_MailManager;

            CStringPairs m_Tokens;

            TPairs<CStringList> m_M2MProfiles;
            TPairs<CStringList> m_SBAProfiles;

            void FetchCerts(CProvider &Provider);

            void FetchProviders();
            void CheckProviders();

            void CheckMessage();

            void SendSMTP(const CPQueryResult &Messages);
            void SendFCM(const CPQueryResult &Messages);
            void SendM2M(const CPQueryResult &Messages);
            void SendSBA(const CPQueryResult &Messages);

            void ProviderAccessToken(const CProvider& Provider);

            CString CreateGoogleToken(const CProvider& Provider, const CString &Application);

            void BeforeRun() override;
            void AfterRun() override;

            bool InProgress(const CString &MsgId);

            void Authentication();
            void Authorize(CStringList &SQL, const CString &Username);

            static void ExecuteObjectAction(CStringList &SQL, const CString &MsgId, const CString &Action);
            static void SetArea(CStringList &SQL, const CString &Area);
            static void SetObjectLabel(CStringList &SQL, const CString &MsgId, const CString &Label);

            static void InitSMTPConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config);
            static void InitM2MConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);
            static void InitSBAConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);

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

            void LoadSMTPConfig(const CString &FileName);
            void LoadFCMConfig(const CString &FileName);

            CSMTPClient *GetSMTPClient(const CSMTPConfig &Config);

            CPQPollQuery *GetQuery(CPollConnection *AConnection) override;

        };
        //--------------------------------------------------------------------------------------------------------------

    }
}

using namespace Apostol::Processes;
}
#endif //APOSTOL_PROCESS_MESSAGE_SERVER_HPP
