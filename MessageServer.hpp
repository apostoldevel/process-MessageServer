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

        struct CAuth {
            CString Username;
            CString Password;

            CString Agent;
            CString Host;

            CString Session;
            CString Secret;
            CString Code;

            void Clear() {
                Username.Clear();
                Password.Clear();

                Agent.Clear();
                Host.Clear();

                Session.Clear();
                Secret.Clear();
                Code.Clear();
            }
        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageServer --------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CMessageServer: public CProcessCustom {
            typedef CProcessCustom inherited;

        private:

            CAuth m_Auth;

            int m_HeartbeatInterval;

            CDateTime m_CheckDate;

            CSMTPManager m_ClientManager;

            void InitServer();
            void CheckMessage();

            void BeforeRun() override;
            void AfterRun() override;

            void AddAuthorize(CStringList &SQL) const;

        protected:

            void DoTimer(CPollEventHandler *AHandler) override;

            void DoHeartbeat();

            void DoDone(CSMTPMessage *AMessage);
            void DoFail(CSMTPMessage *AMessage);

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

            static void LoadConfig(CSMTPConfig &Value);

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
