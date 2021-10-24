/*++

Program name:

  Apostol Web Service

Module Name:

  Connector.cpp

Notices:

  Connectors for Message Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#include "Core.hpp"
#include "Connector.hpp"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Connectors {

        //--------------------------------------------------------------------------------------------------------------

        //-- CCustomConnector ------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CCustomConnector::CCustomConnector(): CObject() {
            m_OnDone = nullptr;
            m_OnFail = nullptr;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CCustomConnector::Done(const CMessage &Message) {
            DoDone(Message);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CCustomConnector::Fail(const CMessage &Message, const CString &Error) {
            DoFail(Message, Error);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CCustomConnector::DoDone(const CMessage &Message) {
            if (m_OnDone != nullptr) {
                m_OnDone(Message);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CCustomConnector::DoFail(const CMessage &Message, const CString &Error) {
            if (m_OnFail != nullptr) {
                m_OnFail(Message, Error);
            }
        }

        //--------------------------------------------------------------------------------------------------------------

        //-- CSMTPConnector --------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        void CSMTPConnector::Init(const CIniFile &IniFile, const CString &Section, CSMTPConfig &Config) {
            Config.Location() = IniFile.ReadString(Section, "host", "http://localhost:25");
            Config.UserName() = IniFile.ReadString(Section, "username", "smtp");
            Config.Password() = IniFile.ReadString(Section, "password", "smtp");
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSMTPConnector::Load(const CString &FileName, CSMTPConfigs &Configs) {
            const CString Prefix(Config()->Prefix());
            CString configFile(FileName);

            if (!path_separator(configFile.front())) {
                configFile = Prefix + configFile;
            }

            if (FileExists(configFile.c_str())) {
                CIniFile IniFile(configFile.c_str());
                IniFile.OnIniFileParseError(OnIniFileParseError);

                CStringList Sections;
                IniFile.ReadSections(&Sections);

                for (int i = 0; i < Sections.Count(); i++) {
                    const auto& Section = Sections[i];
                    int index = Configs.AddPair(Section, CSMTPConfig());
                    auto& Config = Configs[index].Value();
                    Init(IniFile, Section, Config);
                }

                auto& defaultConfig = Configs.Default();
                if (defaultConfig.Name().IsEmpty()) {
                    defaultConfig.Name() = _T("default");
                    auto& Config = defaultConfig.Value();
                    Init(IniFile, defaultConfig.Name(), Config);
                }
            } else {
                Log()->Error(APP_LOG_WARN, 0, APP_FILE_NOT_FOUND, configFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSMTPConnector::Send(const CStringPairs &Data, const CSMTPConfigs &Configs,
                COnGetSMTPClientEvent &&OnClient, COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail) {

            const auto &id = Data.Values("id");
            const auto &profile = Data.Values("profile");

            const auto pos = profile.Find('@');
            const auto &config = pos == CString::npos ? profile : profile.SubString(0, pos);

            const auto &from = Configs[config].UserName();
            const auto &address = Data.Values("address");
            const auto &subject = Data.Values("subject");
            const auto &content = Data.Values("content");

            auto pClient = OnClient(Configs[config]);
            auto &Message = pClient->NewMessage();

            Message.MessageId() = id;
            Message.From() = from;
            Message.To() = address;
            Message.Subject() = subject;
            Message.Body() = content;

            Message.OnDone(std::move(OnDone));
            Message.OnFail(std::move(OnFail));

            pClient->SendMail();
        }

        //--------------------------------------------------------------------------------------------------------------

        //-- CCommonConnector ------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        void CCommonConnector::Init(const CIniFile &IniFile, const CString &Profile, CStringList &Config) {
            IniFile.ReadSectionValues(Profile.c_str(), &Config);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CCommonConnector::Load(const CString &FileName, CStringListPairs &Profiles) {
            LoadConfig(FileName, Profiles, Init);
        }

        //--------------------------------------------------------------------------------------------------------------

        //-- CAPIConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        void CAPIConnector::Send(const CStringPairs &Data, const CStringListPairs &Config, const CStringListPairs &Tokens,
                COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &auth = Sender->Data()["auth"];
                const auto &token = Sender->Data()["token"];
                const auto &content_type = Sender->Data()["content_type"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), content_type.empty() ? _T("application/json") : content_type.c_str());

                if (!token.IsEmpty()) {
                    ARequest->AddHeader(_T("Authorization"), (auth.empty() ? _T("Bearer") : auth) + " " + token);
                }

                DebugRequest(ARequest);
            };

            const auto &id = Data["id"];

            const auto &agent = Data["agent"];
            const auto &area = Data["area"];

            const auto &profile = Data["profile"];
            const auto &address = Data["address"];
            const auto &subject = Data["subject"];
            const auto &content = Data["content"];

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

            pMessage->OnDone(std::move(OnDone));
            pMessage->OnFail(std::move(OnFail));

            const auto& uri = Config[profile]["uri"];
            const auto& auth = Config[profile]["auth"];
            const auto& token = Config[profile]["token"];
            const auto& provider = Config[profile]["provider"].Lower();
            const auto& token_type = Config[profile]["token_type"].Lower();
            const auto& content_type = Config[profile]["content_type"].Lower();

            CLocation URI(uri + (address.front() == '/' ? address : '/' + address));

            auto pClient = OnClient(URI);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("auth", auth);

            if (token_type == "oauth2") {
                pClient->Data().Values("token", Tokens[provider.empty() ? SYSTEM_PROVIDER_NAME : provider]["access_token"]);
            } else {
                pClient->Data().Values("token", token);
            }

            pClient->Data().Values("content_type", content_type);

            pClient->Data().Values("agent", agent);
            pClient->Data().Values("area", area);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(std::move(OnExecute));
            pClient->OnException(std::move(OnException));

            pClient->Active(true);
        }

        //--------------------------------------------------------------------------------------------------------------

        //-- CFCMConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        void CFCMConnector::Send(const CStringPairs &Data, const CStringListPairs &Config, const CStringListPairs &Tokens,
                COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &token = Sender->Data()["token"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/json"));

                ARequest->AddHeader("Authorization", "Bearer " + token);

                DebugRequest(ARequest);
            };

            const auto &id = Data.Values("id");
            const auto &profile = Data.Values("profile");
            const auto &address = Data.Values("address");
            const auto &subject = Data.Values("subject");
            const auto &content = Data.Values("content");

            const auto &provider = Config[profile]["provider"].Lower();
            const auto &token = Tokens[provider.empty() ? GOOGLE_PROVIDER_NAME : provider]["access_token"];

            if (token.IsEmpty())
                return;

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

            pMessage->OnDone(std::move(OnDone));
            pMessage->OnFail(std::move(OnFail));

            const auto &uri = Config[profile]["uri"];

            CLocation URI(uri.IsEmpty() ? CString().Format("https://fcm.googleapis.com/v1/projects/%s/messages:send", profile.c_str()) : uri);

            auto pClient = OnClient(URI);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("token", token);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(std::move(OnExecute));
            pClient->OnException(std::move(OnException));

            pClient->Active(true);
        }

        //--------------------------------------------------------------------------------------------------------------

        //-- CM2MConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        void CM2MConnector::Send(const CStringPairs &Data, const CStringListPairs &Config, const CStringListPairs &Tokens,
                COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail) {

            auto OnRequest = [](CHTTPClient *Sender, CHTTPRequest *ARequest) {

                const auto &uri = Sender->Data()["uri"];
                const auto &token = Sender->Data()["token"];

                auto pMessage = dynamic_cast<CMessage *> (Sender->Data().Objects("message"));
                if (pMessage != nullptr) {
                    ARequest->Content = pMessage->Content();
                }

                CHTTPRequest::Prepare(ARequest, _T("POST"), uri.c_str(), _T("application/soap+xml; charset=utf-8"));

                ARequest->AddHeader("Authorization", "Bearer " + token);

                DebugRequest(ARequest);
            };

            const auto &id = Data.Values("id");

            const auto &agent = Data.Values("agent");
            const auto &area = Data.Values("area");

            const auto &profile = Data.Values("profile");
            const auto &address = Data.Values("address");
            const auto &subject = Data.Values("subject");
            const auto &content = Data.Values("content");

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

            pMessage->OnDone(std::move(OnDone));
            pMessage->OnFail(std::move(OnFail));

            const auto &host = "https://api.mcommunicator.ru/m2m/m2m_api.asmx";

            const auto &uri = Config[profile]["uri"];
            const auto &token = Config[profile]["apikey"];

            CLocation URI(uri.empty() ? host : uri);

            auto pClient = OnClient(URI);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("token", token);

            pClient->Data().Values("agent", agent);
            pClient->Data().Values("area", area);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(std::move(OnExecute));
            pClient->OnException(std::move(OnException));

            pClient->Active(true);
        }

        //--------------------------------------------------------------------------------------------------------------

        //-- CSBAConnector ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        void CSBAConnector::Send(const CStringPairs &Data, const CStringListPairs &Config, const CStringListPairs &Tokens,
                COnGetHTTPClientEvent &&OnClient,
                COnSocketExecuteEvent &&OnExecute, COnSocketExceptionEvent &&OnException,
                COnMessageEvent &&OnDone, COnMessageErrorEvent &&OnFail) {

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

            const auto &id = Data.Values("id");

            const auto &agent = Data.Values("agent");
            const auto &area = Data.Values("area");

            const auto &profile = Data.Values("profile");
            const auto &address = Data.Values("address");
            const auto &subject = Data.Values("subject");
            const auto &content = Data.Values("content");

            auto pMessage = new CMessage();

            pMessage->MessageId() = id;
            pMessage->From() = profile;
            pMessage->To() = address;
            pMessage->Subject() = subject;
            pMessage->Content() = content;

            pMessage->OnDone(std::move(OnDone));
            pMessage->OnFail(std::move(OnFail));

            const auto &host = profile == "test" ? "https://3dsec.sberbank.ru" : "https://securepayments.sberbank.ru";

            const auto &uri = Config[profile]["uri"];
            const auto &userName = Config[profile]["username"];
            const auto &password = Config[profile]["password"];

            CLocation URI((uri.empty() ? host : uri) + (address.front() == '/' ? address : '/' + address));

            auto pClient = OnClient(URI);

            pClient->Data().Values("uri", URI.pathname);
            pClient->Data().Values("username", userName);
            pClient->Data().Values("password", password);

            pClient->Data().Values("agent", agent);
            pClient->Data().Values("area", area);

            pClient->Data().AddObject("message", pMessage);

            pClient->OnRequest(OnRequest);
            pClient->OnExecute(std::move(OnExecute));
            pClient->OnException(std::move(OnException));

            pClient->Active(true);
        }
    }
}

};
