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

        class CMessageHandler;

        typedef std::function<void (CMessageHandler *Handler)> COnMessageHandlerEvent;

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageHandler -------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CMessageServer;
        //--------------------------------------------------------------------------------------------------------------

        class CMessageHandler: public CPollConnection {
        private:

            CMessageServer *m_pServer;
            CAsyncClient *m_pClient;

            CString m_Session {};
            CString m_MessageId {};

            bool m_Allow;

            COnMessageHandlerEvent m_Handler;

            int AddToQueue();
            void RemoveFromQueue();

            void FreeClient();

        protected:

            void SetAllow(bool Value) { m_Allow = Value; }
            void SetClient(CAsyncClient *Value) { m_pClient = Value; }

        public:

            CMessageHandler(CMessageServer *AServer, const CString &Session, const CString &MessageId, COnMessageHandlerEvent && Handler);

            ~CMessageHandler() override;

            const CString &Session() const { return m_Session; }
            const CString &MessageId() const { return m_MessageId; }

            bool Allow() const { return m_Allow; };
            void Allow(bool Value) { SetAllow(Value); };

            CAsyncClient *Client() const { return m_pClient; };
            void Client(CAsyncClient *Value) { SetClient(Value); };

            bool Handler();

            void Close() override;
        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CMessageServer --------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        typedef TPairs<CSMTPConfig> CSMTPConfigs;
        typedef CPollManager CQueueManager;
        //--------------------------------------------------------------------------------------------------------------

        class CMessageServer: public CProcessCustom {
            typedef CProcessCustom inherited;

        private:

            CProcessStatus m_Status;

            CStringList m_Sessions;

            CString m_Agent;
            CString m_Host;

            /// Message in progress send...
            CStringList m_Progress;

            CQueue m_Queue;
            CQueueManager m_QueueManager;

            CProviders m_Providers;

            CSMTPConfigs m_Configs;

            CDateTime m_AuthDate;
            CDateTime m_FixedDate;
            CDateTime m_CheckDate;

            CSMTPManager m_MailManager;

            CStringListPairs m_Tokens;

            TPairs<CStringListPairs> m_Profiles;

            size_t m_MaxMessagesQueue;

            void BeforeRun() override;
            void AfterRun() override;

            void Authentication();
            void SignOut(const CString &Session);

            void CheckListen();
            void InitListen();

            bool InQueue(const CString &MessageId);
            int IndexOfMessage(const CString &MessageId);

            CMessageHandler *GetMessageHandler(const CString &MessageId);

            void FetchCerts(CProvider &Provider, const CString &Application);

            void FetchProviders();
            void CheckProviders();

            void CheckOutbox();
            void CheckTimeOut(CDateTime Now);

            void UnloadMessageQueue();

            void DeleteHandler(CMessageHandler *AHandler);

            void SendMessage(CMessageHandler *AHandler, const TPairs<CString>& Message);
            void SendMessages(const CString &Session, const CPQueryResult& Messages);

            void CreateAccessToken(const CProvider &Provider, const CString &Application, CStringList &Tokens);

            CSMTPClient *GetSMTPClient(const CSMTPConfig &Config);

            static void InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);

            void Heartbeat(CDateTime Now);

        protected:

            void DoTimer(CPollEventHandler *AHandler) override;

            void DoError(const Delphi::Exception::Exception &E);

            void DoMessage(CMessageHandler *AHandler);
            void DoDone(CMessageHandler *AHandler, const CString &Label = CString());
            void DoFail(CMessageHandler *AHandler, const CString &Error);

            void DoSend(const CMessage &Message);
            void DoCancel(const CMessage &Message, const CString &Error);

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

            void DoPQClientException(CPQClient *AClient, const Delphi::Exception::Exception &E) override;
            void DoPQConnectException(CPQConnection *AConnection, const Delphi::Exception::Exception &E) override;

        public:

            explicit CMessageServer(CCustomProcess* AParent, CApplication *AApplication);

            ~CMessageServer() override = default;

            static class CMessageServer *CreateProcess(CCustomProcess *AParent, CApplication *AApplication) {
                return new CMessageServer(AParent, AApplication);
            }

            int AddToQueue(CMessageHandler *AHandler);
            void InsertToQueue(int Index, CMessageHandler *AHandler);
            void RemoveFromQueue(CMessageHandler *AHandler);

            int IndexOfProgress(const CString &MessageId);
            int AddProgress(const CString &MessageId);
            void DeleteProgress(const CString &MessageId);

            CStringList &Progress() { return m_Progress; }
            const CStringList &Progress() const { return m_Progress; }

            CQueue &Queue() { return m_Queue; }
            const CQueue &Queue() const { return m_Queue; }

            CPollManager &QueueManager() { return m_QueueManager; }
            const CPollManager &QueueManager() const { return m_QueueManager; }

            void Run() override;
            void Reload() override;
        };
        //--------------------------------------------------------------------------------------------------------------

    }
}

using namespace Apostol::Processes;
}
#endif //APOSTOL_PROCESS_MESSAGE_SERVER_HPP
