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

            CProviders m_Providers;

            CSMTPConfigs m_Configs;

            int m_HeartbeatInterval;

            CDateTime m_FixedDate;
            CDateTime m_CheckDate;

            CSMTPManager m_MailManager;

            TPairs<CStringPairs> m_Tokens;

            TPairs<CStringList> m_M2MProfiles;
            TPairs<CStringList> m_SBAProfiles;

            void FetchCerts(CProvider &Provider);

            void FetchAccessToken(const CProvider& Provider);

            void FetchProviders();
            void CheckProviders();

            void CheckMessage();

            void SendSMTP(const CPQueryResult &Messages);
            void SendFCM(const CPQueryResult &Messages);
            void SendM2M(const CPQueryResult &Messages);
            void SendSBA(const CPQueryResult &Messages);

            CString CreateServiceToken(const CProvider& Provider, const CString &Application);

            void BeforeRun() override;
            void AfterRun() override;

            bool InProgress(const CString &MsgId);

            static void AddAuthorize(CStringList &SQL, const CString& Username = "mailbot", const CString& Area = "root");
            static void RunAction(CStringList &SQL, const CString &MsgId, const CString &Action);
            static void SetObjectLabel(CStringList &SQL, const CString &MsgId, const CString &Label);
            static void RunAPI(CStringList &SQL, const CString &Path, const CJSON &Payload);

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
            void Reload();

            void LoadSMTPConfig(const CString &FileName);
            void LoadFCMConfig(const CString &FileName);

            static void InitSMTPConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config);

            static void InitM2MConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);
            static void InitSBAConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);

            CSMTPClient *GetSMTPClient(const CSMTPConfig &Config);

            CPQPollQuery *GetQuery(CPollConnection *AConnection) override;

            int HeartbeatInterval() const { return m_HeartbeatInterval; }
            void HeartbeatInterval(int Value) { m_HeartbeatInterval = Value; }

        };
        //--------------------------------------------------------------------------------------------------------------

    }
}

using namespace Apostol::Processes;
}
#endif //APOSTOL_PROCESS_MESSAGE_SERVER_HPP
