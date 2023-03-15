/*++

Program name:

  Apostol CRM

Module Name:

  Connector.hpp

Notices:

  Connectors for Message Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_MESSAGE_SERVER_CONNECTOR_HPP
#define APOSTOL_MESSAGE_SERVER_CONNECTOR_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Connectors {

        //--------------------------------------------------------------------------------------------------------------

        //-- CCustomConnector ------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CCustomConnector: public CObject {
        private:

            CStringListPairs m_Config {};

            COnMessageEvent m_OnDone;
            COnMessageErrorEvent m_OnFail;

        protected:

            void DoDone(const CMessage &Message);
            void DoFail(const CMessage &Message, const CString &Error);

        public:

            CCustomConnector();

            ~CCustomConnector() override = default;

            CStringListPairs &Config() { return m_Config; }
            const CStringListPairs &Config() const { return m_Config; }

            virtual void Send(const CStringPairs &Data) abstract;

            void Done(const CMessage &Message);
            void Fail(const CMessage &Message, const CString &Error);

            const COnMessageEvent &OnDone() const { return m_OnDone; }
            void OnDone(COnMessageEvent && Value) { m_OnDone = Value; }

            const COnMessageErrorEvent &OnFail() const { return m_OnFail; }
            void OnFail(COnMessageErrorEvent && Value) { m_OnFail = Value; }

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CSMTPConnector --------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        typedef std::function<CSMTPClient * (const CSMTPConfig &Config)> COnGetSMTPClientEvent;
        //--------------------------------------------------------------------------------------------------------------

        class CSMTPConnector: public CGlobalComponent {
        public:

            static void Init(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config);
            static void Load(const CString &FileName, CSMTPConfigs &Configs);

            static void Send(const CString &Session, const CStringPairs &Data, const CSMTPConfigs &Configs,
                COnGetSMTPClientEvent &&OnClient, COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail);

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CCommonConnector ------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CCommonConnector: public CGlobalComponent {
        public:

            static void Init(const CIniFile &IniFile, const CString &Profile, CStringList &Config);
            static void Load(const CString &FileName, CStringListPairs &Profiles);

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CAPIConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CAPIConnector: public CCommonConnector {
        public:

            static void Send(const CString &Session, const CStringPairs &Data, const CStringListPairs &Config,
                const CStringListPairs &Tokens, COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail);

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFCMConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFCMConnector: public CCommonConnector {
        public:

            static void Send(const CString &Session, const CStringPairs &Data, const CStringListPairs &Config,
                const CStringListPairs &Tokens, COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail);

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CM2MConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CM2MConnector: public CCommonConnector {
        public:

            static void Send(const CString &Session, const CStringPairs &Data, const CStringListPairs &Config,
                const CStringListPairs &Tokens, COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail);

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CSBAConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CSBAConnector: public CCommonConnector {
        public:

            static void Send(const CString &Session, const CStringPairs &Data, const CStringListPairs &Config,
                const CStringListPairs &Tokens, COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail);

        };
    }
}

};

#endif //APOSTOL_MESSAGE_SERVER_CONNECTOR_HPP
