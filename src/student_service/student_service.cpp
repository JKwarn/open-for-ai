#define WIN32_LEAN_AND_MEAN // 从 Windows 头文件中排除极少使用的内容
#include <WinSock2.h>
#include <windows.h>
#include <Lmcons.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <tchar.h>

#include <iostream>
#include <optional>
#include <filesystem>
#include <span>

#include "student_service.h"
#include "common/log/log.h"
#include "common/os-software/network/sock.h"
#include "common/os-software/network/udp/multicast.h"
#include "common/os-hardware/network-adapter/adapter.h"

#pragma comment(lib, "ws2_32.lib")

static SERVICE_STATUS gServiceStatus;
static SERVICE_STATUS_HANDLE gStatusHandle;
static constexpr char gHostLoggerName[]{ "host" };
bool xixi_host_service::running = false;
static std::deque<std::string> gTasks;
HANDLE gTaskEvent{NULL};
TCHAR gAppDataPath[MAX_PATH]{ 0 };

using ce_t = os::software::network::udp::control_event_t;
ce_t gCE{ { ce_t::type_t::kClose, ce_t::type_t::kPause, ce_t::type_t::kContinue} };

struct sender_ip_info
{
    sockaddr_in IPv4Addr{ 0 };
    char IPv4Str[20]{ 0 };
    uint16_t IPv4Port{ 0 };
};

// 用于日志记录
template<typename T>
    requires (std::is_convertible_v<T, std::string> ||std::is_convertible_v<T, std::wstring>)
static void log_message(int level, const T& message)
{
    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file(gHostLoggerName) };
    if(log)
    {
        log->write_log(level, message);
    }
}

::DWORD get_process_pid(const str::xview& process_name)
{
    ::PROCESSENTRY32 pe32{ 0 };
    pe32.dwSize = sizeof(::PROCESSENTRY32);
    ::HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    ::DWORD ret{ 0 };
    if(::Process32First(hSnapshot, &pe32))
    {
        do
        {
            if(::_tcscmp(pe32.szExeFile, process_name.data()) == 0)
            {
                ret = pe32.th32ProcessID;
                break;
            }
        } while(::Process32Next(hSnapshot, &pe32));
    }
    ::CloseHandle(hSnapshot);
    return ret;
}

::HANDLE get_process_token(::DWORD pid)
{
    ::HANDLE ret{ NULL };
    do
    {
        ::HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if(NULL == hProcess)
        {
            break;
        }

        ::HANDLE hToken{ NULL };
        if(FALSE == ::OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
        {
            ::CloseHandle(hProcess);
            break;
        }

        ::DWORD needed_size{ 0 };
        ::GetTokenInformation(hToken, TokenUser, NULL, 0, &needed_size);
        ::PTOKEN_USER pTokenUser = (::PTOKEN_USER)::malloc(needed_size);
        /*
        if(nullptr == pTokenUser)
        {}
        */
        if(FALSE == ::GetTokenInformation(hToken, TokenUser, pTokenUser, needed_size, &needed_size))
        {
            ::CloseHandle(hToken);
            ::CloseHandle(hProcess);
            ::free(pTokenUser);
            break;
        }
        else
        {
            if(FALSE == ::DuplicateToken(hToken, SECURITY_IMPERSONATION_LEVEL::SecurityAnonymous, &ret))
            {
                auto dr = ::GetLastError();
                ret = NULL;
            }
        }

        ::CloseHandle(hToken);
        ::CloseHandle(hProcess);
        ::free(pTokenUser);

    } while(0);

    return ret;
}

std::optional<std::filesystem::path> resolve_shortcut(const str::xtype& shortcut_path)
{
    std::optional<std::filesystem::path> target_path{ std::nullopt };
    ::IShellLink* pShellLink = nullptr;
    ::IPersistFile* pPersistFile = nullptr;
    do
    {
        auto ret = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&pShellLink);
        if(!SUCCEEDED(ret))
        {
            auto ret_copy = static_cast<std::make_unsigned_t<decltype(ret)>>(ret);
            log_message(common::log::level_enum::err, WLogText("failed to cocreate {:x}.{}", ret_copy, shortcut_path));
            break;
        }

        ret = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
        if(!SUCCEEDED(ret))
        {
            auto ret_copy = static_cast<std::make_unsigned_t<decltype(ret)>>(ret);
            log_message(common::log::level_enum::err, WLogText("failed to query {:x}.{}", ret_copy, shortcut_path));
            break;
        }

        ret = pPersistFile->Load(shortcut_path.c_str(), STGM_READ);
        if(!SUCCEEDED(ret))
        {
            auto ret_copy = static_cast<std::make_unsigned_t<decltype(ret)>>(ret);
            log_message(common::log::level_enum::err, WLogText("failed to load {:x}.{}", ret_copy, shortcut_path));
            break;
        }

        TCHAR path[MAX_PATH]{ 0 };
        ret = pShellLink->GetPath(path, MAX_PATH, nullptr, SLGP_SHORTPATH);
        if(SUCCEEDED(ret))
        {
            target_path = path;
        }
        else
        {
            auto ret_copy = static_cast<std::make_unsigned_t<decltype(ret)>>(ret);
            log_message(common::log::level_enum::err, WLogText("failed to get {:x}.{}", ret_copy, shortcut_path));
        }

    } while(0);

    if(pPersistFile)
    {
        pPersistFile->Release();
        pPersistFile = nullptr;
    }

    if(pShellLink)
    {
        pShellLink->Release();
        pShellLink = nullptr;
    }

    return target_path;
}

bool get_desktop_path(std::vector<str::xtype>& out_value)
{
    bool no_err{ false };
    do
    {
        auto pid = get_process_pid(TEXT("explorer.exe"));
        if(pid == 0)
        {
            log_message(common::log::level_enum::err, WLogText("failed to get PID {} ", ::GetLastError()));
            break;
        }

        auto token = get_process_token(pid);
        if(token == NULL)
        {
            log_message(common::log::level_enum::err, WLogText("failed to get token {} ", ::GetLastError()));
            break;
        }


        TCHAR path[MAX_PATH]{ 0 };
        constexpr std::uint32_t csids[]{ CSIDL_COMMON_DESKTOPDIRECTORY, CSIDL_DESKTOPDIRECTORY, CSIDL_LOCAL_APPDATA, CSIDL_COMMON_APPDATA, CSIDL_APPDATA };
        HRESULT ret = S_OK;
        for(const auto& ele : std::span{ csids, 2 })
        {
            ret = ::SHGetFolderPath(NULL, ele, token, 0, path);
            if(FAILED(ret))
            {
                log_message(common::log::level_enum::err, WLogText("failed to get desktop {:#x} ", static_cast<std::make_unsigned_t<decltype(ret)>>(ret)));
            }
            else
            {
                out_value.emplace_back(path);
            }
        }

        for(const auto& ele : std::span{ csids + 2, std::size(csids) - 2 })
        {
            ret = ::SHGetFolderPath(NULL, ele, token, 0, gAppDataPath);
            if(SUCCEEDED(ret))
            {
                log_message(common::log::level_enum::err, WLogText("new:{} ", gAppDataPath));
                break;
            }
        }

        if(gAppDataPath[0] == TEXT('\0'))
        {
            ::memcpy(gAppDataPath, TEXT("c:/"), 4 * sizeof(TCHAR));
            log_message(common::log::level_enum::err, WLogText("failed to get app data {:#x} ", static_cast<std::make_unsigned_t<decltype(ret)>>(ret)));
        }

        no_err = true;
        ::CloseHandle(token);

    } while(0);

    return no_err;
}

bool delete_shortcut()
{
    log_message(common::log::level_enum::trace, WLogText("delete shortcut beg"));

    bool no_err{ false };

    do
    {
        if(RPC_E_CHANGED_MODE == ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))
        {
            if(RPC_E_CHANGED_MODE == ::CoInitializeEx(nullptr, COINIT_MULTITHREADED))
            {
                log_message(common::log::level_enum::err, WLogText("failed to CoInitialize"));
                break;
            }
        }

        std::vector<str::xtype> paths;
        if(false == get_desktop_path(paths))
            break;

        log_message(common::log::level_enum::trace, WLogText("paths count = {}", paths.size()));

        str::xtype lnk_path;
        std::optional<std::filesystem::path> exe_path;
        std::filesystem::path parent_path;
        BOOL delet_exe = FALSE;
        BOOL delet_lnk = FALSE;
        DWORD delet_exe_er = 0;
        DWORD delet_lnk_er = 0;
        for(const auto& ele : paths)
        {
            delet_exe_er = 0;
            delet_lnk_er = 0;
            lnk_path = ele + TEXT("\\习习考试.lnk");
            exe_path = resolve_shortcut(lnk_path);
            if(!exe_path)
            {
                log_message(common::log::level_enum::trace, WLogText("not exists {}", lnk_path));
                continue;
            }

            if(exe_path->filename() != (TEXT("习习向上.exe")))
            {
                log_message(common::log::level_enum::trace, WLogText("not the target file:{}", exe_path->generic_wstring()));
                continue;
            }

            parent_path = exe_path->parent_path();
            if(std::filesystem::exists(parent_path / "top.exe") && std::filesystem::exists(parent_path / "mic.exe"))
            {
                delet_lnk = ::DeleteFile(lnk_path.c_str());
                delet_lnk_er = ::GetLastError();
                delet_exe = ::DeleteFile(exe_path->c_str());
                delet_exe_er = ::GetLastError();
                no_err = (FALSE == delet_exe || FALSE == delet_lnk);
                if(no_err)
                {
                    log_message(common::log::level_enum::trace, WLogText("failed to delete {}.{}", delet_exe_er, delet_lnk_er));
                }
                else
                {
                    log_message(common::log::level_enum::trace, WLogText("delete {} {}", lnk_path, exe_path->generic_wstring()));
                }
            }
        }

    } while(0);
    ::CoUninitialize();
    log_message(common::log::level_enum::trace, WLogText("delete shortcut end"));
    return no_err;
};

void xixi_host_service::service_main(DWORD argc, LPWSTR* argv)
{
    os::software::network::udp::multicast multcast;
    gStatusHandle = ::RegisterServiceCtrlHandler(gKServiceName, &xixi_host_service::service_ctrl_handler);
    if(!gStatusHandle)
    {
        log_message(common::log::level_enum::err, WLogText_A(".{} failed to register service control handler",::GetLastError()));
        report_service_status(SERVICE_STOP_PENDING, SERVICE_STOPPED, 0);
        return;
    }


    bool no_err = false;
    do
    {
        host_config conf;
        if(!do_start())
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} failed to start", ::GetLastError()));
            break;
        }

        if(!read_host_config(conf))
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} failed to read", ::GetLastError()));
            break;
        }

        gServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        gServiceStatus.dwCurrentState = SERVICE_START_PENDING;
        gServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        gServiceStatus.dwWin32ExitCode = 0;
        gServiceStatus.dwServiceSpecificExitCode = 0;
        gServiceStatus.dwCheckPoint = 0;
        gServiceStatus.dwWaitHint = 0;

        report_service_status(SERVICE_START_PENDING, NO_ERROR, 6000);
        delete_shortcut();
        no_err = true;
    } while(0);


    if(no_err)
    {
        report_service_status(SERVICE_RUNNING, NO_ERROR, 0);
        os::software::network::udp::multicast multcast;
        multcast.set_temp_path(gAppDataPath);
        os::hardware::network::mac_ip_container candidate;
        running = true;
        do
        {
            candidate = os::hardware::network::adapter::get_mac_ip();
            log_message(common::log::level_enum::trace, WLogText_A("retrieved {} network interfaces", candidate.size()));
            if(false == candidate.empty())
            {
                auto remove_func = [](decltype(candidate)::value_type& ele)->bool
                    {
                        constexpr std::string_view zero{ "0.0.0.0" };
                        return zero == ele.ipv4;
                    };

                candidate.erase(std::remove_if(candidate.begin(), candidate.end(), remove_func), candidate.end());
                if(candidate.empty())
                {
                    log_message(common::log::level_enum::warn, WLogText_A("empty container"));
                    ::Sleep(3000);
                    continue;
                }

                std::uint16_t failed_create_count{ 0 };
                constexpr std::uint16_t max_failed_count{ 50 };
                auto iter = candidate.cbegin();
                try
                {
                    do
                    {
                        log_message(common::log::level_enum::trace, WLogText_A("create a connection using ipv4 {}", iter->ipv4));
                        if(multcast.create(iter->ipv4, gKRemoteGroupIpv4, gKDefaultPort, gCE))
                        {
                            log_message(common::log::level_enum::trace, WLogText_A("run begin"));
                            multcast.run();
                            running = false; 
                            log_message(common::log::level_enum::trace, WLogText_A("run over"));
                            break;
                        }
                        else
                        {
                            log_message(common::log::level_enum::trace, WLogText_A("create failed"));
                            ++iter;
                            ++failed_create_count;
                        }

                        if(iter == candidate.end())
                        {
                            log_message(common::log::level_enum::warn, WLogText_A("sentinel reached;wrapping around to head"));
                            iter = candidate.begin();
                        }
                        else if(failed_create_count < max_failed_count)
                        {
                            log_message(common::log::level_enum::err, WLogText_A("too many errors detected; terminating program"));
                            break;
                        }

                        ::Sleep(6000);

                    } while(failed_create_count < max_failed_count);
                }
                catch(const std::exception& e)
                {
                    log_message(common::log::level_enum::exception, WLogText_A("{}", e.what()));
                    running = false;
                }
                catch(...)
                {
                    log_message(common::log::level_enum::exception, WLogText_A("!!!"));
                    running = false;
                }
            }
            else
            {
                log_message(common::log::level_enum::warn, WLogText_A("container has no data,try again"));
                ::Sleep(2000);
            }

        } while(running);
    }

    report_service_status(SERVICE_STOPPED, NO_ERROR, 0);
};

void xixi_host_service::service_ctrl_handler(DWORD ctrl_code)
{
    switch(ctrl_code)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        do_stop();
        break;
    case SERVICE_CONTROL_PAUSE:
        break;
    case SERVICE_CONTROL_CONTINUE:
        break;
    default:
        break;
    }
}

bool xixi_host_service::do_start()
{
    log_message(common::log::level_enum::trace, "service starting...");
    return true;
}

void xixi_host_service::do_stop()
{
    if(running)
    {
        gCE.set_event(ce_t::type_t::kClose);
        running = false;
    }
    report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    log_message(common::log::level_enum::trace, "service stopping...");
}

void xixi_host_service::do_pause()
{
    if(running)
    {
        gCE.set_event(ce_t::type_t::kPause);
        log_message(common::log::level_enum::trace, "service pause...");
    }
    report_service_status(SERVICE_PAUSED, NO_ERROR, 0);
}

void xixi_host_service::do_continue()
{
    if(running)
    {
        gCE.set_event(ce_t::type_t::kContinue);
        log_message(common::log::level_enum::trace, "service continue...");
    }
    report_service_status(SERVICE_RUNNING, NO_ERROR, 0);
}

void xixi_host_service::report_service_status(uint32_t currentState, uint32_t exitCode, uint32_t waitHint)
{
    static DWORD check_point = 1;

    gServiceStatus.dwCurrentState = currentState;
    gServiceStatus.dwWin32ExitCode = exitCode;
    gServiceStatus.dwWaitHint = waitHint;

    switch(gServiceStatus.dwCurrentState)
    {
    case SERVICE_RUNNING:
    case SERVICE_STOPPED:
        gServiceStatus.dwCheckPoint = 0;
        break;
    default:
        gServiceStatus.dwCheckPoint = check_point++;
        break;
    }

    if(gServiceStatus.dwCurrentState == SERVICE_START_PENDING)
        gServiceStatus.dwControlsAccepted = 0;
    else 
        gServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    ::SetServiceStatus(gStatusHandle, &gServiceStatus);
}

bool xixi_host_service::read_host_config(host_config& out)
{
    out = host_config{};
    return true;
}