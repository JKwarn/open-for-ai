#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <WinSock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <userenv.h>
#include <tlhelp32.h>
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Wtsapi32.lib")

#include <thread>
#include <system_error>
#include <chrono>
#include <functional>
#include <type_traits>
#include <shared_mutex>
#include <condition_variable>
#include <fstream>
#include <expected>
#include <set>

#include "multicast.h"
#include "common/string_define.h"
#include "common/log/log.h"
#include "common/log/logger_help.h"
#include "common/json/json.h"
#include "common/encode/string/string-encode.h"
#include "common/os-hardware/network-adapter/adapter.h"
#include "common/os-software/network/sock.h"
#include "common/os-software/info/sys.h"
#include "common/os-software/process/process.h"
#include "common/os-software/info/app.h"
#include "common/fmt/fmt-pch.h"



//template<typename T>
//    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
//static void log_message(int level, const T& message)
//{
//    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("opengui") };
//    if(log)
//    {
//        log->write_log(level, message);
//    }
//}


namespace xixi
{
    struct exam_config
    {
        int EnableProxy{ 0 };
        std::string ServerAPIIP{ 0 };
        std::string ServerAPIPort{ 0 }; 
        std::string exitPwd{ 0 };
        std::uint32_t HostServicePort{ 0 };
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(exam_config, EnableProxy, ServerAPIIP, ServerAPIPort, exitPwd, HostServicePort);
    };


    void log_open_error(common::log::logger_help& logger, const str::xtype& file_path)
    {
        namespace fs = std::filesystem;
        const fs::path& path{ file_path };
        std::error_code ec;
        if(!fs::exists(path, ec))
        {
            logger.log_message(common::log::level_enum::err,
                               WLogText_A("file {} not exist:{}", path.string(), ec.message()));
            return;
        }

        if(fs::is_directory(path, ec))
        {
            logger.log_message(common::log::level_enum::err,
                               WLogText("path {} is directory", file_path));
            return;
        }

        auto perms = fs::status(path, ec).permissions();
        if((perms & fs::perms::owner_read) == fs::perms::none)
        {
            logger.log_message(common::log::level_enum::err,
                               WLogText("no read {} permission", file_path));
            return;
        }

#ifdef _WIN32
        ::DWORD err = ::GetLastError();
        ::LPSTR msg = nullptr;
        ::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                        nullptr,
                        err,
                        0,
                        (::LPSTR)&msg,
                        0,
                        nullptr
        );
        logger.log_message(common::log::level_enum::err,
                           WLogText_A("open {} failed {}: {}", path.string(), err, msg));
        ::LocalFree(msg);
#else
        log_message(common::log::level_enum::err,
                    WLogText("open {} failed {}: {}", file_path, errno, strerror(errno)));
#endif
    }

    template<typename T>
    std::expected<void, std::string> write_config_to_file(const std::filesystem::path& file_path, const T& data)
    {
        std::string why;
        do
        {
            try
            {
                nlohmann::json json_obj = data;
                std::ofstream out(file_path, std::ios_base::trunc | std::ios_base::out);
                if(false == out.is_open())
                {
                    why = WLogText_A("failed to open file: {}", file_path.generic_string());
                    break;
                }

                out << json_obj.dump(4) << '\n'; 
                if(!out)
                {
                    why = WLogText_A("failed to write {} data: {}", file_path.generic_string(), ::GetLastError());
                    break;
                }
            }
            catch(const std::exception& exception)
            {
                why = WLogText_A("failed to write, exception: {}", exception.what());
                break;
            }

        } while(0);

        if(false != why.empty())
            return std::unexpected(why);
    }

    template<typename T>
    std::expected<T, std::string> read_config_from_file(const std::filesystem::path& file_path)
    {
        std::string why;
        T data{};
        do
        {
            try
            {
                std::ifstream in(file_path, std::ios::in);
                if(false == in.is_open())
                {
                    why = WLogText_A("failed to open file: {}", file_path.generic_string());
                    break;
                }

                nlohmann::json json_obj;
                in >> json_obj;
                data = json_obj.get<T>();
            }
            catch(const std::exception& exception)
            {
                why = WLogText_A("failed to read, exception: {}", exception.what());
                break;
            }


        } while(0);

        if(why.empty())
            return data;
        else
            return std::unexpected(why);
    }

}// end namespace xixi

#include <wtsapi32.h>
bool get_active_seesion_id(common::log::logger_help& logger, ::DWORD& out)
{
    bool no_err{ false };
    do
    {
        ::PWTS_SESSION_INFO sessions_buff{ nullptr };
        ::DWORD session_count{ 0 };
        ::BOOL success = ::WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,
                                                 0,
                                                 1,
                                                 &sessions_buff,
                                                 &session_count
        );

        if(FALSE == success)
        {
            logger.log_message(common::log::level_enum::debug, WLogText("failed to enumerate {}", ::GetLastError()));
            break;
        }

        for(std::size_t i = 0; i < session_count; i++)
        {
            ::WTS_SESSION_INFO& session = sessions_buff[i];
            if(::WTS_CONNECTSTATE_CLASS::WTSActive == session.State)
            {
                out = session.SessionId;
                no_err = true;
                break;
            }
        }

        if(false == no_err)
        {
            logger.log_message(common::log::level_enum::debug, WLogText("failed to get, no active {}.{}", static_cast<void*>(sessions_buff),session_count));
        }

        if(sessions_buff) 
        {
            ::WTSFreeMemory(sessions_buff);
        }

    } while(0);

    return no_err;
}


#include <tchar.h>
#include <list>
std::vector<::DWORD> GetThreadIdsByProcessId(::DWORD processId)
{
    std::vector<::DWORD> threadIds;
    ::HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(hSnapshot != INVALID_HANDLE_VALUE)
    {
        ::THREADENTRY32 threadEntry = {};
        threadEntry.dwSize = sizeof(::THREADENTRY32);
        if(::Thread32First(hSnapshot, &threadEntry))
        {
            do
            {
                if(threadEntry.th32OwnerProcessID == processId)
                {
                    threadIds.push_back(threadEntry.th32ThreadID);
                }
            } while(::Thread32Next(hSnapshot, &threadEntry));
        }
        ::CloseHandle(hSnapshot);
    }
    return threadIds;
}

::BOOL CALLBACK EnumWindowsProcByPid(::HWND hWnd, ::LPARAM lParam)
{
    ::DWORD target_pid = *reinterpret_cast<::DWORD*>(lParam);
    ::DWORD window_pid = 0;
    GetWindowThreadProcessId(hWnd, &window_pid);
    if(window_pid == target_pid)
    {
        *reinterpret_cast<::HWND*>(lParam) = hWnd;
        return FALSE;
    }
    lParam = NULL;
    return TRUE;
}


bool get_process_id(common::log::logger_help& logger, const str::xtype& process_name, ::DWORD& target_pid)
{
    bool no_err{false};
    do
    {
        ::HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
        if(INVALID_HANDLE_VALUE == snapshot)
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to create snapshot {}", ::GetLastError()));
            break;
        }

        ::PROCESSENTRY32 pe32{ 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32);
        ::BOOL first = ::Process32First(snapshot, &pe32);
        bool find{ false };
        std::list<str::xtype> enum_history;
        while(first)
        {
            if(0 == ::_tcscmp(pe32.szExeFile, process_name.data()))
            {
                no_err = true;
                target_pid = pe32.th32ProcessID;
                break;
            }
            enum_history.emplace_back(pe32.szExeFile);
            first = ::Process32Next(snapshot, &pe32);;
        }
        ::CloseHandle(snapshot);
        if(!no_err)
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to get {}. {:n} ", process_name, enum_history));
        }

    } while(0);

    return no_err;
}


bool IsImpersonationToken(common::log::logger_help& logger, ::HANDLE hToken)
{
    ::TOKEN_TYPE tokenType;
    ::DWORD returnLength;
    if(FALSE == GetTokenInformation(hToken, TokenType,&tokenType,sizeof(tokenType),&returnLength))
    {
        logger.log_message(common::log::level_enum::debug, WLogText("falied to GetTokenInformation {} ", ::GetLastError()));
        return false;
    }

    return (tokenType == TokenImpersonation);
}


bool IsRunAsAdmin(common::log::logger_help& logger, ::HANDLE h, bool& y1, bool& y2)
{
    ::BOOL isAdmin = FALSE;
    ::PSID adminGroupSid = NULL;
    ::SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if(FALSE == ::AllocateAndInitializeSid(&ntAuthority, 2,
                                           SECURITY_BUILTIN_DOMAIN_RID,
                                           DOMAIN_ALIAS_RID_ADMINS,
                                           0, 0, 0, 0, 0, 0,&adminGroupSid))
    {
        logger.log_message(common::log::level_enum::debug, WLogText("falied to get AllocateAndInitializeSid {} ", ::GetLastError()));
        return false;
    }

    if(FALSE == ::CheckTokenMembership(NULL, adminGroupSid, &isAdmin))
    {
        isAdmin = FALSE;
        y1 = false;
        logger.log_message(common::log::level_enum::debug, WLogText("falied to CheckTokenMembership {} ", ::GetLastError()));
    }
    else
    {
        y1 = isAdmin != FALSE;
    }

    ::HANDLE hImpersonationToken{ NULL };
    if(false == IsImpersonationToken(logger, h))
    {
        ::TOKEN_TYPE tokenType = TokenImpersonation;
        ::SECURITY_IMPERSONATION_LEVEL impersonationLevel = SecurityImpersonation;

        if(FALSE == ::DuplicateTokenEx(h,TOKEN_QUERY | TOKEN_IMPERSONATE,NULL,
                                       impersonationLevel,tokenType,&hImpersonationToken))
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to DuplicateTokenEx {} ", ::GetLastError()));
        }
        else
        {
            h = hImpersonationToken;
        }
    }

    if(FALSE == ::CheckTokenMembership(h, adminGroupSid, &isAdmin))
    {
        y2 = false;
        logger.log_message(common::log::level_enum::debug, WLogText("falied to CheckTokenMembership {} ", ::GetLastError()));
    }
    else
    {
        y2 = isAdmin != FALSE;
    }

    ::FreeSid(adminGroupSid);
    return isAdmin != FALSE;
}


::BOOL EnablePrivilege(common::log::logger_help& logger, HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnable)
{
    ::LUID luid;
    if(!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        logger.log_message(common::log::level_enum::debug, WLogText(".{}", ::GetLastError()));
        return FALSE;
    }

    ::TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(::TOKEN_PRIVILEGES), NULL, NULL))
    {
        logger.log_message(common::log::level_enum::debug, WLogText(".{}", ::GetLastError()));
        return FALSE;
    }

    if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        logger.log_message(common::log::level_enum::debug, WLogText(".{}", ::GetLastError()));
        return FALSE;
    }

    return TRUE;
}


bool create_env_process(common::log::logger_help& logger,
                        ::HANDLE token,
                        const std::filesystem::path& app_path,
                        const str::xtype& app_param,
                        ::DWORD create_process_flags,
                        str::xtype::value_type* workstation = nullptr)
{
    bool no_err{ false };
    do
    {
        void* env_block = NULL;
        if(FALSE == ::CreateEnvironmentBlock(&env_block, token, FALSE))
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to create env {}.{}", token, ::GetLastError()));
            ::CloseHandle(token);
            break;
        }

        ::STARTUPINFO startup_info{ 0 };
        startup_info.cb = sizeof(::STARTUPINFO);
        if(workstation)
        {
            startup_info.lpDesktop = workstation;
        }


        ::PROCESS_INFORMATION process_information{ 0 };

        str::xtype::value_type cmd[MAX_PATH]{ 0 };
        for(size_t i = 0; i < app_param.length(); i++)
        {
            cmd[i] = app_param[i];
        }

        const auto& app_path_str = app_path.generic_wstring();
        ::BOOL create_ok = ::CreateProcessAsUser(token,
                                                 app_path_str.c_str(),
                                                 cmd,
                                                 NULL,
                                                 NULL,
                                                 FALSE,
                                                 create_process_flags,
                                                 env_block,
                                                 NULL,
                                                 &startup_info,
                                                 &process_information
        );

        ::DestroyEnvironmentBlock(env_block);
        ::CloseHandle(token);
        if(create_ok)
        {
            ::CloseHandle(process_information.hProcess);
            ::CloseHandle(process_information.hThread);
            no_err = true;
        }
        else
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to create process {}.{}.{}.{}", app_path_str, cmd, create_process_flags, ::GetLastError()));
        }

    } while(0);

    return no_err;
}


bool opengui(common::log::logger_help& logger, const str::xtype& app_path, str::xtype app_param)
{
    logger.log_message(common::log::level_enum::trace, WLogText("opengui"));
    bool no_err{ false };
    do
    {
        ::DWORD session_id{ 0 };
        if(false == get_active_seesion_id(logger, session_id))
        {
            break;
        }

        ::HANDLE token{ NULL };
        if(FALSE == ::WTSQueryUserToken(session_id, &token))
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to query{}.{}", session_id, ::GetLastError()));
            break;
        }

        ::TCHAR workstation[]{ TEXT("WinSta0\\Default") };
        no_err = create_env_process(logger, token, app_path, app_param, CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS, workstation);

    } while(0);

    return no_err;
}

bool opengui3(common::log::logger_help& logger, const std::filesystem::path& app_path, const str::xtype& app_param)
{
    logger.log_message(common::log::level_enum::trace, WLogText("open [{}].[{}]", app_path.generic_wstring(), app_param));
    bool no_err{ false };
    do
    {
        ::DWORD pid{ 0 };
        str::xtype process_name { TEXT("winlogon.exe") };
        if(false == get_process_id(logger, process_name, pid))
        {
            break;
        }

        auto target_process = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if(NULL == target_process)
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to open process {}.{}", pid, ::GetLastError()));
            break;
        }

        ::HANDLE token{ NULL };
        ::DWORD process_access{ TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE 
                                | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE };
        if(FALSE == ::OpenProcessToken(target_process, process_access, &token))
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to open token {}.{}", pid, ::GetLastError()));
            break;
        }

        ::HANDLE dup_token{ NULL }; TOKEN_ALL_ACCESS; MAXIMUM_ALLOWED;
        if(FALSE == ::DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &dup_token))
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to duplicate {}", ::GetLastError()));
            ::CloseHandle(token);
            break;
        }


        ::DWORD session_id{ 0 };
        if(false == get_active_seesion_id(logger, session_id))
        {
            break;
        }

        if(FALSE == ::SetTokenInformation(dup_token, TokenSessionId, &session_id, sizeof(::DWORD)))
        {
            logger.log_message(common::log::level_enum::debug, WLogText("falied to set {}.{}", session_id, ::GetLastError()));
            ::CloseHandle(dup_token);
            ::CloseHandle(token);
            break;
        }


        ::TCHAR workstation[]{ TEXT("WinSta0\\Default") };
        no_err = create_env_process(logger, dup_token, app_path, app_param, 
                                    CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT, 
                                    workstation);

    } while(0);

    return no_err;
}

::HANDLE GetCurrentUserToken(common::log::logger_help& logger)
{
    PWTS_SESSION_INFO pSessionInfo = 0;
    ::DWORD dwCount = 0;
    ::WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &dwCount);
    int session_id = -1;
    for(::DWORD i = 0; i < dwCount; ++i)
    {
        WTS_SESSION_INFO si = pSessionInfo[i];
        if(WTSActive == si.State)
        {
            session_id = si.SessionId;
            break;
        }
    }
    ::WTSFreeMemory(pSessionInfo);
    ::HANDLE current_token = 0;
    ::BOOL bRet = ::WTSQueryUserToken(session_id, &current_token);
    int errorcode = GetLastError();
    if(bRet == FALSE)
    {
        logger.log_message(common::log::level_enum::debug, WLogText("{}.{}", session_id,errorcode));
        return 0;
    }

    logger.log_message(common::log::level_enum::debug, WLogText("session_id =  {}", session_id));

    ::HANDLE primaryToken = 0;
    bRet = ::DuplicateTokenEx(current_token, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &primaryToken);
    errorcode = GetLastError();
    ::CloseHandle(current_token);
    if(bRet == FALSE)
    {
        logger.log_message(common::log::level_enum::debug, WLogText("{}.{}", session_id,errorcode));
        return 0;
    }

    return primaryToken;
}


::BOOL RunAdminPrivilege(common::log::logger_help& logger, const str::xtype& app_path, const str::xtype& app_param)
{
    logger.log_message(common::log::level_enum::trace, WLogText("RunAdminPrivilege"));
    ::HANDLE primaryToken = GetCurrentUserToken(logger);
    if(primaryToken == 0)
    {
        return FALSE;
    }

    ::HANDLE hUnfilteredToken = NULL;
    ::DWORD dwSize = 0;
    bool go{ false };
aaaa:
    if(FALSE == GetTokenInformation(primaryToken, TokenLinkedToken, (VOID*)&hUnfilteredToken, sizeof(HANDLE), &dwSize))
    {
        logger.log_message(common::log::level_enum::debug, WLogText(".{}", ::GetLastError()));
        hUnfilteredToken = primaryToken;
    }

    if(false == create_env_process(logger, primaryToken, app_path, app_param,
                                   CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT))
    {
        logger.log_message(common::log::level_enum::debug, WLogText(".{}", ::GetLastError()));

        if(!go)
        {
            go = true;
            goto aaaa;
        }
    }

    ::CloseHandle(primaryToken);

    return TRUE;
}

bool opengui2(common::log::logger_help& logger, const str::xtype& app_path, str::xtype app_param)
{
    logger.log_message(common::log::level_enum::trace, WLogText_A("to opengui"));
    {
        auto app_mutext = ::OpenMutex(READ_CONTROL, FALSE , TEXT("Global\\XiXiUpWebStudent@Instance"));
        if(NULL != app_mutext)
        {
            logger.log_message(common::log::level_enum::trace, WLogText("open {} succeed", app_path));
            return true;
        }
    }

    ::HANDLE hToken = nullptr;
    ::HANDLE hProcessSnap = nullptr;
    ::PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(::PROCESSENTRY32);

    hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(INVALID_HANDLE_VALUE == hProcessSnap)
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui", ::GetLastError()));
        return FALSE;
    }
    if(FALSE == Process32First(hProcessSnap, &pe32))
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui", ::GetLastError()));
        return FALSE;
    }
    do
    {
        if(_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0)
        {
            ::HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if(NULL == hProcess)
            {
                logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui", ::GetLastError()));
                return FALSE;
            }
            if(FALSE == ::OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
            {
                logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui", ::GetLastError()));
                return FALSE;
            }
            ::CloseHandle(hProcessSnap);
            break;
        }
    } while(::Process32Next(hProcessSnap, &pe32));

    if(NULL == hToken)
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui", ::GetLastError()));
        return false;
    }

    ::HANDLE hTokenDup = NULL;
    ::BOOL bRet = ::DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &hTokenDup);
    if(!bRet || hTokenDup == NULL)
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui{}{}", ::GetLastError(), bRet, static_cast<void*>(hTokenDup)));
        CloseHandle(hToken);
        return false;
    }

    ::DWORD dwSessionId = ::WTSGetActiveConsoleSessionId();
    ::BOOL setR = ::SetTokenInformation(hTokenDup, TokenSessionId, &dwSessionId, sizeof(DWORD));
    if(FALSE == setR)
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui{}.{}.{}", ::GetLastError(), setR,
                                                                     static_cast<void*>(hTokenDup),
                                                                     static_cast<void*>(hToken)));
        ::CloseHandle(hTokenDup);
        ::CloseHandle(hToken);
        return false;
    }

    ::STARTUPINFO si;
    ::ZeroMemory(&si, sizeof(::STARTUPINFO));

    si.cb = sizeof(::STARTUPINFO);
    TCHAR workstation[]{ TEXT("WinSta0\\Default") };
    si.lpDesktop = workstation;
    si.wShowWindow = SW_SHOW;
    si.dwFlags = STARTF_USESHOWWINDOW;

    LPVOID pEnv = NULL;
    bRet = ::CreateEnvironmentBlock(&pEnv, hTokenDup, FALSE);
    if(FALSE == bRet)
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui{}.{}.{}", ::GetLastError(), setR,
                                                                     static_cast<void*>(hTokenDup),
                                                                     static_cast<void*>(hToken)));
        ::CloseHandle(hTokenDup);
        ::CloseHandle(hToken);
        return false;
    }

    if(pEnv == NULL)
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui{}.{}.{}", ::GetLastError(), setR,
                                                                     static_cast<void*>(hTokenDup),
                                                                     static_cast<void*>(hToken)));
        ::CloseHandle(hTokenDup);
        ::CloseHandle(hToken);
        return false;
    }

    ::PROCESS_INFORMATION processInfo;
    ::ZeroMemory(&processInfo, sizeof(::PROCESS_INFORMATION));
    ::DWORD dwCreationFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;

    ::BOOL creatR = ::CreateProcessAsUser(hTokenDup, app_path.c_str(), app_param.data(), NULL, NULL, FALSE, dwCreationFlag, pEnv, NULL, &si, &processInfo);
    if(FALSE == creatR)
    {
        logger.log_message(common::log::level_enum::err, WLogText_A(".{} failed to opengui{}.{}.{}", ::GetLastError(), setR,
                                                                     static_cast<void*>(hTokenDup),
                                                                     static_cast<void*>(hToken)));
        ::CloseHandle(hTokenDup);
        ::CloseHandle(hToken);
        return false;
    }

    ::CloseHandle(processInfo.hProcess);
    ::CloseHandle(processInfo.hThread);
    ::DestroyEnvironmentBlock(pEnv);
    ::CloseHandle(hTokenDup);
    ::CloseHandle(hToken);

    return true;
}


namespace os::software::network::udp
{
    class control_event_t::impl : public common::log::logger_help
    {
    public:
        impl(type_container_t types);
        ~impl();

        HANDLE  get_signle_event(type_t dest);
        std::size_t  get_signle_event_index(type_t dest);
        HANDLE* get_events();
        void set_event(type_t dest);
        std::size_t get_count() const;
        bool is_close_event(std::size_t index)const;
        bool wait_specified_event(const type_t& type, std::uint32_t timeout);
        void wait_specified_event(const type_t& type, std::uint32_t timeout, callback_t func);

    private:
        type_container_t mTypes;
        event_container_t mEvents;
        std::size_t mCloseIndex;
    };
};

namespace os::software::network::udp
{
    os::software::network::udp::control_event_t::impl::impl(type_container_t types)
        :
        logger_help("event"),
        mTypes(std::move(types)),
        mCloseIndex(std::string::npos)
    {
        static_assert(std::is_same_v<control_event_t::HANDLE, ::HANDLE>, "HANDLE not same");

        try
        {
            if(mTypes.empty())
                return;
            std::size_t index = 0;
            auto fun = [this, &index](const type_container_t::value_type& e)
                {
                    if(MAXIMUM_WAIT_OBJECTS == index)
                    {
                        log_message(common::log::level_enum::err, WLogText_A("too more, failed to create{}", static_cast<int>(e)));
                        return true;
                    }


                    ::HANDLE result = ::CreateEvent(NULL, FALSE, FALSE, NULL);
                    if(!result)
                    {
                        log_message(common::log::level_enum::err, WLogText_A(".{} failed to create", ::GetLastError()));
                    }
                    else
                    {
                        mEvents.push_back(result);
                        if( e == type_container_t::value_type::kClose)
                        {
                            mCloseIndex = index;
                        }
                    }
                    ++index;
                    return result ? false : true;
                };

            const auto& r = std::remove_if(mTypes.begin(), mTypes.end(), fun);

        }
        catch(const std::exception& s)
        {
            auto why = s.what();
            mTypes.clear();
            for(auto iter : mEvents)
            {
                ::CloseHandle(iter);
            }
        }
    }

    control_event_t::impl::~impl()
    {
        mTypes.clear();
        for(auto iter : mEvents)
        {
            ::CloseHandle(iter);
        }
    }


    HANDLE control_event_t::impl::get_signle_event(type_t dest)
    {
        HANDLE result = NULL;
        auto length = mTypes.size();
        for(size_t i = 0; i < length; i++)
        {
            if(dest != mTypes[i])
                continue;

            ::DWORD temp = 0;
            if(::GetHandleInformation(mEvents[i], &temp))
            {
                result = mEvents[i];
                break;
            }
            else
            {
                auto errCode = ::GetLastError();
            }
        }
        return result;
    }

    std::size_t control_event_t::impl::get_signle_event_index(type_t dest)
    {
        if(dest == type_t::kClose)
        {
            return mCloseIndex;
        }

        std::size_t i = 0;
        auto iter = mTypes.cbegin();
        while(iter != mTypes.cend())
        {
            if(dest == *iter)
            {
                return i;
            }
            ++i;
            ++iter;
        }

        return std::string::npos;
    }

    HANDLE* control_event_t::impl::get_events()
    {
        return mEvents.empty() ? NULL : mEvents.data();
    }

    void control_event_t::impl::set_event(type_t dest)
    {
        auto handle = get_signle_event(dest);
        if(handle)
        {
            ::SetEvent(handle);
        }
    }

    std::size_t control_event_t::impl::get_count() const
    {
        return mEvents.size();
    }

    bool control_event_t::impl::is_close_event(std::size_t index) const
    {
        return index == mCloseIndex;
    }

    bool control_event_t::impl::wait_specified_event(const type_t& type, std::uint32_t timeout)
    {
        auto index = get_signle_event_index(type);
        if(index == std::string::npos)
        {
            log_message(common::log::level_enum::err, WLogText_A("{} not that", static_cast<int>(type)));
            return false;
        }

        ::DWORD result = ::WaitForMultipleObjects(mEvents.size(), mEvents.data(), FALSE, timeout);
        if(0 != timeout && index != std::string::npos)
        {
            log_message(common::log::level_enum::err, WLogText_A("{} misses of expectations {}", result, static_cast<int>(type)));
            return false;
        }

        return result == WAIT_OBJECT_0 + index;
    }

    void control_event_t::impl::wait_specified_event(const type_t& type, std::uint32_t timeout, callback_t func)
    {
        if(wait_specified_event(type, timeout))
        {
            func(wait_result_t::kSignaled);
        }
    }
};

namespace os::software::network::udp
{
    control_event_t::control_event_t(type_container_t types)
        : mImpl(std::make_shared<impl>(std::move(types)))
    {}

    control_event_t::~control_event_t() = default;

    //control_event_t& udp::control_event_t::operator=(const control_event_t& other)
    //{
    //    *mImpl.get() = *const_cast<control_event_t&>(other).mImpl.get();
    //    //mImpl.swap(const_cast<control_event_t&>(other).mImpl);
    //    return *this;
    //}

    HANDLE control_event_t::get_signle_event(type_t dest)
    {
        return mImpl->get_signle_event(dest);
    }

    HANDLE* control_event_t::get_events()
    {
        return mImpl->get_events();
    }

    void control_event_t::set_event(type_t dest)
    {
        mImpl->set_event(dest);
    }

    std::size_t control_event_t::get_count() const
    {
        return mImpl->get_count();
    }

    bool udp::control_event_t::is_close_event(std::size_t index) const
    {
        return mImpl->is_close_event(index);
    }

    bool control_event_t::wait_specified_event(const type_t& types, std::uint32_t timeout)
    {
        return mImpl->wait_specified_event(types, timeout);
    }

    void udp::control_event_t::wait_specified_event(const type_t& type, std::uint32_t timeout, callback_t func)
    {
        mImpl->wait_specified_event(type, timeout, func);
    }

    bool udp::control_event_t::wait_close_event(std::uint32_t timeout)
    {
        return mImpl->wait_specified_event(type_t::kClose, timeout);
    }
};

namespace os::software::network::udp
{
    enum class host_event
    {
        Unknown,
        Exception,
        Open,
        Close,
        Install,
        Ignore,
    };


    class multicast::impl : public common::log::logger_help
    {
    public:
        explicit impl();
        ~impl()=default;

        using task_t = std::pair<std::string, std::string>;
        using task_deque_t = std::deque<task_t>;

        void do_work();
        void do_parse(std::stop_token stopToken, std::condition_variable& task_cv);
        void push_task(const task_t& task, bool front = false);
        void copy_task(task_deque_t& out_value);
        network::udp::host_event parse_host_event(const task_t& json_obj, nlohmann::json& out);
        void do_open_event(const nlohmann::json& json_obj);
        void do_close_event(const nlohmann::json& json_obj);
        void do_install_event(const nlohmann::json& json_obj);

        bool join_ipv4_remote_group(SOCKET fd, const std::string_view& native_ipv4, const std::string_view& remote_group_ipv4, ::ip_mreq& out_value);

        bool create(std::string native_ipv4, std::string remote_ipv4, int multicast_port, control_event_t& out_value);
        void run();
        void stop();

        void set_temp_path(const std::filesystem::path& obj);

    private:
        class handle;
        static const std::vector<std::pair<std::string_view, host_event>> mValidTask;

    private:
        common::log::logger_ptr mLoggers;
        std::unique_ptr<handle> mFd;
        control_event_t mContrlEvent;
        std::shared_mutex mWRmutex;
        task_deque_t mTasksDeque;
        ::ip_mreq mMreq{ 0 };
        std::filesystem::path mOsTempPath;
    };

    const std::vector<std::pair<std::string_view, host_event>> multicast::impl::mValidTask{
        {"openXixiExam",host_event::Open},
        {"closeXixiExam",host_event::Close},
        {"installXixiExam",host_event::Install},
    };

    constexpr std::string_view kSupervisionMachineIPv4{ "supervision_ip" };
}

namespace os::software::network::udp
{
    class multicast::impl::handle
    {
    public:
        using type = sock_fd;
        explicit handle(type handle);
        ~handle();
        handle(const handle&) = default;
        handle& operator=(const handle&) = delete;
        type get_copy() const;
        void unuse();
        void reset(type newHandle);
        operator bool() const;

    private:
        sock_fd mHandle;
    };
}

namespace os::software::network::udp
{
    multicast::impl::handle::handle(type handle)
        : mHandle(handle)
    {}

    multicast::impl::handle::~handle()
    {
        reset(INVALID_SOCKET);
    }

    multicast::impl::handle::type multicast::impl::handle::get_copy() const
    {
        return mHandle;
    }

    void multicast::impl::handle::unuse()
    {
        if(mHandle != INVALID_SOCKET)
        {
            ::shutdown(mHandle, SD_BOTH);
        }
    }

    void multicast::impl::handle::reset(type newHandle)
    {
        if(mHandle != INVALID_SOCKET)
        {
            ::shutdown(mHandle, SD_BOTH);
            ::closesocket(mHandle);
        }
        mHandle = newHandle;
    }

    multicast::impl::handle::operator bool() const
    {
        return mHandle != INVALID_SOCKET;
    }
}

namespace os::software::network::udp
{
    multicast::impl::impl()
        :
        logger_help("multicast"),
        mContrlEvent(control_event_t::type_container_t())
    {
    }

    void multicast::impl::do_work()
    {
        log_message(common::log::level_enum::trace, "worker on line");

        constexpr int buffer_size{ 1024 };
        char buffer[buffer_size]{ 0 };
        sender_ipv4_info_t sender;
        int senderAddrLen = sizeof(sender.addr);
        int bytesReceived = 0;

        std::condition_variable task_cv;
        std::jthread parse_thread{ [this, &task_cv](std::stop_token stoken){do_parse(stoken, std::ref(task_cv));} };

        auto fd = mFd->get_copy();
        std::map<std::uint32_t, std::string> historical_sender;
        std::string_view sender_ip_v4_view;

        while(true)
        {
            if(mContrlEvent.wait_close_event(0))
                break;

            if(mContrlEvent.wait_specified_event(control_event_t::type_t::kPause, 0))
            {
                log_message(common::log::level_enum::trace, "wait continue");
                mContrlEvent.wait_specified_event(control_event_t::type_t::kContinue);
                log_message(common::log::level_enum::trace, "now continue");
            }

            bytesReceived = ::recvfrom(fd, buffer, buffer_size - 1, 0, (sockaddr*)&sender.addr, &senderAddrLen);
            if(sock::call_ntop(AF_INET, &sender.addr.sin_addr, sender.str, std::size(sender.str)))
            {
                sender_ip_v4_view = sender.str;
                const auto uint_ip_v4 = sender.addr.sin_addr.S_un.S_addr;
                auto iter = historical_sender.find(uint_ip_v4);
                if(historical_sender.cend() == iter)
                {
                    historical_sender.emplace(uint_ip_v4, sender_ip_v4_view);
                }
            }
            else
                sender_ip_v4_view = "";

            if(0 == bytesReceived)
            {
                log_message(common::log::level_enum::info, WLogText_A(".{:s} closed", sender.str));
                break;
            }
            else if(SOCKET_ERROR == bytesReceived)
            {
                if(10060 == ::WSAGetLastError())
                    continue;
                else
                {
                    log_message(common::log::level_enum::err, WLogText_A("{:s} failed {}", sender.str, ::GetLastError()));
                    break;
                }
            }
            else
            {
#ifdef _DEBUG
                log_message(common::log::level_enum::trace, WLogText_A("{:s} recv{} [{}]", sender.str, bytesReceived, buffer));
#endif // _DEBUG
                buffer[bytesReceived] = '\0';
            }

            push_task(std::make_pair(std::string(buffer), std::string(sender_ip_v4_view)));
            task_cv.notify_all();
        }

        if(parse_thread.joinable())
        {
            parse_thread.request_stop();
            parse_thread.join();
        }
        mFd->unuse();
        int drop = ::setsockopt(mFd->get_copy(), IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&mMreq, sizeof(mMreq));
        log_message(common::log::level_enum::trace, WLogText_A("worker off line:{}", drop));
    }

    void multicast::impl::do_parse(std::stop_token stopToken, std::condition_variable& task_cv)
    {
        decltype(mTasksDeque) tasks_copy;
        std::mutex task_m;
        std::unique_lock<std::mutex>  task_guard{ task_m };
        std::cv_status wait_result;
        std::uint8_t step{ 0 };
        std::uint64_t parse_count {0};
        std::filesystem::path config_path;
        std::filesystem::path app_dir = info::app<info::get::kDirPath>();
        config_path = app_dir / TEXT("ProxyConfigInfo.json");

        auto not_ignore_func = [&config_path, this](const nlohmann::json& json_obj, host_event event)
            {
                bool not_ignore = false;
                do
                {
                    if(false == std::filesystem::exists(config_path))
                    {
                        log_message(common::log::level_enum::trace, WLogText_A("config file not exists"));
                        not_ignore = true;
                        break;
                    }

                    const auto& ret = xixi::read_config_from_file<xixi::exam_config>(config_path);
                    if(ret.has_value())
                    {
                        const std::string& recv_ipv4 = json_obj.at(kSupervisionMachineIPv4);
                        const auto& config_ip = ret.value().ServerAPIIP;
                        if(config_ip == recv_ipv4 || config_ip.empty())
                        {
                            not_ignore = true;
                        }
                        else
                        {
                            log_message(common::log::level_enum::trace,
                                       WLogText_A("{} ignore {}, from {}", config_ip, static_cast<int>(event), recv_ipv4));
                        }
                    }
                    else
                    {
                        log_message(common::log::level_enum::trace, 
                                    WLogText_A("failed to read {} {}", config_path.generic_string(), ret.error()));
                        not_ignore = true;
                    }

                } while(0);

                return not_ignore;
            };

        log_message(common::log::level_enum::trace, "task on line");
        nlohmann::json data;
        bool already_write = true;
        std::uint64_t last_write_value{ 0 };
        std::uint64_t write_scale{ 100 };
        std::uint64_t write_count{ 0 };
        try
        {
            while(!stopToken.stop_requested())
            {
                step = 1;
                wait_result = task_cv.wait_for(task_guard, std::chrono::seconds(2));
                if(wait_result == std::cv_status::timeout)
                    continue;

                step = 2;
                copy_task(tasks_copy);
                parse_count += tasks_copy.size();
                step = 3;


                if(already_write && (parse_count - last_write_value) > write_scale)
                {
                    already_write = false;
                }

                while(false == tasks_copy.empty())
                {
                    switch(parse_host_event(tasks_copy.front(), data))
                    {
                    case host_event::Open:
                    {
                        if(not_ignore_func(data, host_event::Open))
                        {
                            do_open_event(data);
                        }
                    }
                    break;
                    case host_event::Close:
                    {
                        if(not_ignore_func(data, host_event::Close))
                        {
                            do_close_event(data);
                        }
                    }
                    break;
                    case host_event::Install:
                    {
                        if(not_ignore_func(data, host_event::Install))
                        {
                            do_install_event(data);
                        }
                    }
                    break;
                    default:
                        break;
                    }

                    tasks_copy.pop_front();
                }

                if(false == already_write)
                {
                    log_message(common::log::level_enum::trace, WLogText_A("task processed:{}", parse_count));
                    already_write = true;
                    if(++write_count % 10 == 0)
                    {
                        write_scale *= 10;
                    }
                    last_write_value = (parse_count / write_scale) * write_scale;
                }

                //for(const auto& ele : tasks_copy)
                //{
                //    switch(parse_host_event(ele))
                //    {
                //    case host_event::Open:
                //        unique_task.emplace_back(host_event::Open);
                //        break;
                //    case host_event::Close:
                //        unique_task.emplace_back(host_event::Close);
                //        break;
                //    default:
                //        break;
                //    }
                //}

                //tasks_copy.clear();
                //step = 4;
                //auto last = std::unique(unique_task.begin(), unique_task.end());
                //unique_task.erase(last, unique_task.end());
                //step = 5;
                //for(const auto& ele : unique_task)
                //{
                //    switch(ele)
                //    {
                //    case host_event::Open:
                //        do_open_event();
                //        break;
                //    case host_event::Close:
                //        do_close_event();
                //        break;
                //    default:
                //        break;
                //    }
                //}
            }
        }
        catch(const std::exception& e)
        {
            log_message(common::log::level_enum::exception, WLogText_A("{}.{} exception in do", e.what(), step));
        }

        log_message(common::log::level_enum::trace, WLogText_A("task off line, processed:{}", parse_count));
    }

    void multicast::impl::push_task(const task_t& task, bool front)
    {
        std::unique_lock lock(mWRmutex);
        if(front)
            mTasksDeque.emplace_front(task);
        else
            mTasksDeque.emplace_back(task);
    }

    void multicast::impl::copy_task(task_deque_t& out_value)
    {
        std::shared_lock lock(mWRmutex);
        out_value.swap(mTasksDeque);
    }

    network::udp::host_event multicast::impl::parse_host_event(const task_t& task_data, nlohmann::json& out)
    {
/*
    四、考试机发打开学生机消息格式：
    {
            "event": "openXixiExam",
            "data" : {
                    "date": new Date().toLocaleString(),
                    "testMode": 0或1
            }
    }

    五、考试机发关闭学生机消息格式：
    {
            "event": "closeXixiExam",
            "data" : {
                    "date": new Date().toLocaleString()
            }
    }

    六、安装
    {
            "event": "installXixiExam",
            "data" : {
                    "path": "proxy/download/XixiExam?filename=XixiExam.7z",(自己拼ip)
                    "version": "2.2.2.51",
                    "md5": "a4c82d6dc12dce420a2d2866aa2c3140",
                    "date": new Date().toLocaleString()
             }
    }
*/
        host_event ret_value{ host_event::Unknown};
        static std::set<std::string> no_match;
        do
        {
            try
            {
                const auto& json_obj = nlohmann::json::parse(task_data.first);
                const std::string& recv_event = json_obj.at("event");
                for(auto& ele : mValidTask)
                {
                    if(ele.first == recv_event)
                    {
                        ret_value = ele.second;
                        out = json_obj.at("data");
                        out[kSupervisionMachineIPv4] = task_data.second;
                        break;
                    }
                }

                if(ret_value == host_event::Unknown && no_match.count(recv_event) == 0)
                {
                    no_match.emplace(recv_event);
                    log_message(common::log::level_enum::trace, WLogText_A("{} no match found", recv_event));
                }
            }
            catch(const std::exception& exception)
            {
                log_message(common::log::level_enum::exception, WLogText_A("{} failed to parse {} ", task_data.first, exception.what()));
                ret_value = host_event::Exception;
            }

        } while(0);

        return ret_value;
    }

    void multicast::impl::do_open_event(const nlohmann::json& json_obj)
    {
        using namespace os::software;
        std::filesystem::path app_dir = info::app<info::get::kDirPath>();
        std::filesystem::path app_path;
        if(false == app_path.empty())
        {
            app_path = app_dir / TEXT("习习考试.exe");
        }
        else
        {
            app_path = TEXT("./习习考试.exe");
        }

        auto app_mutext = ::OpenMutex(READ_CONTROL, FALSE, TEXT("Global\\XiXiUpWebStudent@Instance"));
        if(NULL != app_mutext)
        {
            ::CloseHandle(app_mutext);
            log_message(common::log::level_enum::trace, WLogText("{} is already running", app_path.generic_wstring()));
        }
        else
        {
            const std::string date = json_obj["date"];
            int testMode = json_obj.contains("testMode") ? json_obj["testMode"].get<int>() : 0;
            int debugMode = json_obj.contains("debugMode") ? json_obj["debugMode"].get<int>() : 0;
            const auto param = xfmt::format(TEXT("flag=open; date={}; testMode={}; debugMode={}"), encode::string::utf8_to_utf16(date), testMode, debugMode);

#ifdef _DEBUG
            constexpr auto exe = TEXT(R"(D:\ProjectWork\XiXiExam2\bin\debug\习习考试.exe)");
            app_path = exe;
#endif
            opengui3(*this, app_path, param);
        }

        ::Sleep(2000);
    }

    void multicast::impl::do_close_event(const nlohmann::json& json_obj)
    {
        std::filesystem::path app_dir = info::app<info::get::kDirPath>();
        std::filesystem::path app_path;
        if(false == app_path.empty())
        {
            app_path  = app_dir / TEXT("关闭习习考试.exe");
        }
        else
        {
            app_path = TEXT("./关闭习习考试.exe");
        }

        auto exam_mutext = ::OpenMutex(SYNCHRONIZE, FALSE, TEXT("Global\\XiXiUpWebStudent@Instance"));
        str::xtype param;
        if(NULL == exam_mutext)
        {
            ::DWORD error = GetLastError();
            if(error == ERROR_FILE_NOT_FOUND)
            {
                log_message(common::log::level_enum::trace, WLogText("{} is not running", app_path.generic_wstring()));
            }
            else
            {
                log_message(common::log::level_enum::err, WLogText("{} status {} is uncertain", app_path.generic_wstring(), error));
            }
        }
        else
        {
            ::CloseHandle(exam_mutext);
            auto app_mutext = ::OpenMutex(SYNCHRONIZE, FALSE, TEXT("Global\\XiXiExam@CloseStudent"));
            if(NULL == app_mutext)
            {
                ::DWORD error = GetLastError();
                if(ERROR_FILE_NOT_FOUND != error)
                {
                    log_message(common::log::level_enum::err, WLogText("{} status {} is uncertain", app_path.generic_wstring(), error));
                }

#ifdef _DEBUG
                constexpr auto exe = TEXT(R"(D:\ProjectWork\XiXiExam2\bin\debug\关闭习习考试.exe)");
                app_path = exe;
#endif
                const std::string& ip = json_obj[kSupervisionMachineIPv4];
                std::uint32_t uint_ipv4{ 0 };
                if(network::sock::call_pton(AF_INET, ip.c_str(), &uint_ipv4))
                {
                    param = xfmt::format(TEXT("20250207 {}"), uint_ipv4);
                }
                else
                {
                    param = xfmt::format(TEXT("20250207"));
                }
                opengui3(*this, app_path, param);
            }
            else
            {
                ::CloseHandle(app_mutext);
                log_message(common::log::level_enum::trace, WLogText("app already running"));
            }
        }

        ::Sleep(2000);
    }

    void multicast::impl::do_install_event(const nlohmann::json& json_obj)
    {
    /*
    六、安装
    {
            "event": "installXixiExam",
            "data" : {
                    //http://192.168.12.209:3127/proxy/download/XixiExam?filename=XixiExam.7z
                    "path": "proxy/download/XixiExam?filename=XixiExam.7z",(自己拼ip)
                    "version": "2.2.2.51",
                    "md5": "a4c82d6dc12dce420a2d2866aa2c3140",
                    "date": new Date().toLocaleString()
                    "supervision_ip": "192.168.12.9"(额外写入的)
             }
    }
    */
        ::HANDLE app_mutex{ NULL };
        do
        {
            app_mutex = ::CreateMutex(NULL, TRUE, TEXT("Global\\XiXiUpWebStudent@Instance"));
            ::DWORD err_code = ::GetLastError();
            if(NULL == app_mutex)
            {
                log_message(common::log::level_enum::err, WLogText("an error occurred {}", err_code));
                break;
            }
            else
            {
                if(ERROR_ALREADY_EXISTS == err_code)
                {
                    ::CloseHandle(app_mutex);
                    app_mutex = NULL;
                    log_message(common::log::level_enum::trace, WLogText("exam app is running. ignore install"));
                    break;
                }
            }

            std::filesystem::path old_dir = info::app<info::get::kDirPath>();
            std::filesystem::path app_path;
            if(old_dir.empty())
            {
                old_dir = TEXT("./");
            }

            constexpr const char* const files[]{ "update.exe", "wget.exe", "contract.json" };
            const auto& new_dir = mOsTempPath / "taixu-acfun-huanjing";
            app_path = new_dir / files[0];

            try
            {
                if(mOsTempPath.empty())
                {
                    throw std::runtime_error("must not be empty");
                }

                std::filesystem::create_directory(new_dir);
                for(auto ele : files)
                {
                    if(std::filesystem::exists(old_dir / ele))
                    {
                        std::filesystem::copy_file(old_dir / ele, new_dir / ele, std::filesystem::copy_options::overwrite_existing);
                    }
                }
            }
            catch(const std::filesystem::filesystem_error& exception)
            {
                log_message(common::log::level_enum::exception, WLogText_A("{}", exception.what()));
                break;
            }
            catch(const std::bad_alloc& exception)
            {
                log_message(common::log::level_enum::exception, WLogText_A("failed to copy {}", exception.what()));
                break;
            }
            catch(const std::exception& exception)
            {
                log_message(common::log::level_enum::exception, WLogText_A("failed to copy {}", exception.what()));
                break;
            }

            str::xtype cmd;
            auto update_mutext = ::OpenMutex(SYNCHRONIZE, FALSE, TEXT("Global\\XixiExam@Update"));
            if(NULL == update_mutext)
            {
                err_code = GetLastError();
                if(err_code == ERROR_FILE_NOT_FOUND)
                {
                    try
                    {
                        str::xtype path{ encode::string::utf8_to_utf16(json_obj.at("path")) };
                        str::xtype version{ encode::string::utf8_to_utf16(json_obj.at("version")) };
                        str::xtype md5{ encode::string::utf8_to_utf16(json_obj.at("md5")) };
                        str::xtype date{ encode::string::utf8_to_utf16(json_obj.at("date")) };
                        str::xtype ip{ encode::string::utf8_to_utf16(json_obj.at("supervision_ip")) };
                        str::xtype install_location = old_dir.generic_wstring();
                        cmd = xfmt::format(TEXT("http://{}:3127/{} {} {} \"{}\" {} {}"), ip, path, version, md5, date, ip, install_location);
                    }
                    catch(const std::exception& exception)
                    {
                        log_message(common::log::level_enum::exception, WLogText_A("{} failed to run {}", app_path.generic_string(), exception.what()));
                        break;
                    }
                    opengui3(*this, app_path, cmd);
                }
                else
                {
                    log_message(common::log::level_enum::err, WLogText("{} status {} is uncertain", app_path.generic_wstring(), err_code));
                }
            }
            else
            {
                ::CloseHandle(update_mutext);
                log_message(common::log::level_enum::trace, WLogText("install is running. ignore install"));
            }

        } while(0);

        if(app_mutex)
        {
            ::ReleaseMutex(app_mutex);
            ::CloseHandle(app_mutex);
        }

        ::Sleep(2000);
    }

    bool multicast::impl::join_ipv4_remote_group(SOCKET fd, const std::string_view& native_ipv4, 
                                                 const std::string_view& remote_group_ipv4, ::ip_mreq& out_value)
    {
        bool no_error = false;
        do
        {
            out_value = { 0 };
            if(false == sock::call_pton(AF_INET, remote_group_ipv4.data(), &out_value.imr_multiaddr.s_addr))
            {
                break;
            }

            ::sockaddr ipv4_addr;
            int lenv = sizeof(ipv4_addr);
            auto get_result = ::getsockname(fd, &ipv4_addr, &lenv);
            if(SOCKET_ERROR == get_result)
            {
                log_message(common::log::level_enum::err_debug_wnd, WLogText_A("{}.{}.{}.{} failed to get join {}",
                                                                               fd, native_ipv4, get_result, ::WSAGetLastError(), remote_group_ipv4)
                );
                break;
            }

            out_value.imr_interface.s_addr = ((sockaddr_in*)&ipv4_addr)->sin_addr.S_un.S_addr;
            if(SOCKET_ERROR == ::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&out_value, sizeof(out_value)))
            {
                log_message(common::log::level_enum::err_debug_wnd, WLogText_A("{}.{}.{}.{}.{} failed to join {}",
                                                                               fd, get_result, native_ipv4, out_value.imr_interface.s_addr,
                                                                               ::WSAGetLastError(), remote_group_ipv4)
                );
                break;
            }

            no_error = true;
            log_message(common::log::level_enum::trace, WLogText_A("{} join {}", native_ipv4, remote_group_ipv4));
        } while(0);

        return no_error;
    }

    bool multicast::impl::create(std::string native_ipv4, std::string remote_group_ipv4, int multicast_port, control_event_t& out_value)
    {
        auto func = [](sock_fd fd)
            {
                network::sock::set_sock_reuse_addr(fd);
                network::sock::set_sock_recv_out_time(fd, 2, 0);
            };

        //native_ipv4 = "192.168.12.19";
        mFd = std::make_unique<handle>(
            network::sock::create_sock_ipv4(network::sock::type::kUDP, native_ipv4, multicast_port, func)
        );

        ::sockaddr_in localAddr{ 0 };
        localAddr.sin_family = AF_INET;
        localAddr.sin_port = ::htons(multicast_port);
        log_message(common::log::level_enum::trace, WLogText_A("check {} ", native_ipv4.c_str()));
        if(false == sock::call_pton(AF_INET, native_ipv4.c_str(), &localAddr.sin_addr))
        {
            return false;
        }

        if(SOCKET_ERROR == ::bind(mFd->get_copy(), (sockaddr*)&localAddr, sizeof(localAddr)))
        {
            log_message(common::log::level_enum::err_debug_wnd, WLogText_A("{}.{}.{} failed to start.{}",
                                                                           native_ipv4, mFd->get_copy(), multicast_port,
                                                                           ::WSAGetLastError()));
            return false;
        }

        if(false == join_ipv4_remote_group(mFd->get_copy(), native_ipv4, remote_group_ipv4, mMreq))
        {
            return false;
        }

        mContrlEvent = out_value;
        log_message(common::log::level_enum::trace, "ready to work");
        return true;
    }

    void multicast::impl::run()
    {
        do_work();
    }

    void multicast::impl::stop()
    {
        mContrlEvent.set_event(control_event_t::type_t::kClose);
    }

    void multicast::impl::set_temp_path(const std::filesystem::path& obj)
    {
        mOsTempPath = obj;
    }

};

namespace os::software::network::udp
{
    multicast::multicast()
        : mImpl(std::make_unique<impl>())
    {}

    multicast::~multicast()
    {}

    bool multicast::create(const std::string& local_ipv4, const std::string& remote_group_ipv4, int multicast_port, control_event_t& out_value)
    {
        return mImpl->create(local_ipv4, remote_group_ipv4, multicast_port, out_value);
    }

    void multicast::run()
    {
        mImpl->run();
    }

    void multicast::stop()
    {
        mImpl->stop();
    }

    void multicast::set_temp_path(const std::filesystem::path& obj)
    {
        mImpl->set_temp_path(obj);
    }
};
