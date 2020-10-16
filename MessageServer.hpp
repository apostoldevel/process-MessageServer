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

            CSMTPConfigs m_Configs;

            int m_HeartbeatInterval;

            CDateTime m_CheckDate;

            CSMTPManager m_ClientManager;

            void CheckMessage();

            void BeforeRun() override;
            void AfterRun() override;

            static void AddAuthorize(CStringList &SQL);
            static void RunAction(CStringList &SQL, const CString &MsgId, const CString &Action);
            static void SetObjectLabel(CStringList &SQL, const CString &MsgId, const CString &Label);

            static void AddMIME(const CString &MsgId, const CString &From, const CString &To, const CString &Subject,
                                const CString &Body, CSMTPMessage &Message);

        protected:

            void DoTimer(CPollEventHandler *AHandler) override;

            void DoHeartbeat();
            void DoError(const Delphi::Exception::Exception &E);

            void DoSend(const CSMTPMessage &Message);
            void DoDone(const CSMTPMessage &Message);

            void DoCancel(const CSMTPMessage &Message, const CString &Error);
            void DoFail(const CSMTPMessage &Message, const CString &Error);

            void DoRequest(CObject *Sender);
            void DoReply(CObject *Sender);

            void DoConnected(CObject *Sender);
            void DoDisconnected(CObject *Sender);

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

            void LoadSMTPConfig(const CString &FileName);
            static void InitConfig(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config);

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
