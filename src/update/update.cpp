// update.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "update.h"
#include <windows.h>
#include <commctrl.h>
#include <Wincrypt.h>
#include <Urlmon.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <WtsApi32.h>
#include <userenv.h>
#include <shellapi.h>
#include <optional>
#include <fstream>
#include <vector>
#include <thread>
#include <cwctype>


#pragma comment(lib, "common-lib.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "WtsApi32.lib") 
#pragma comment(lib, "userenv.lib") 


#include "common/string_define.h"
#include "common/log/log.h"
#include "common/log/logger_help.h"
#include "common/json/json.h"
#include "common/encode/string/string-encode.h"
#include "common/os-software/process/process.h"
#include "common/os-software/info/app.h"
#include "common/fmt/fmt-pch.h"
#include "common/windows/regedit/regedit.h"

HWND gHprogress;
HWND gHwnd;
HWND gLabel = NULL;
std::atomic<bool> gUpdateError = false;
#define TIMER_ID 1
#define WM_TEST_COMMAND WM_USER+0x1

template<typename T>
    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
static void log_message(int level, const T& message)
{
    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("update") };
    if(log)
    {
        log->write_log(level, message);
    }
}


enum exit_code_t
{
    kCreateMutexError = -9,
    kCommandLineInvalid,
    kLaunchViaDoubleClick,
    kUpdateException,
    kArgumentCountBelowMin,
};

std::optional<std::size_t> get_tmp(const TCHAR* p)
{
    if(nullptr == p)
    {
        return std::nullopt;
    }


    if(*p == TEXT('\0'))
    {
        return 0;
    }


    std::size_t len{ 0 };
    std::size_t last_end{ 0 };
    std::wstring_view v;

    while(1)
    {
        if(p[len++] == TEXT('\0') && p[len] == TEXT('\0'))
        {
            len = -1;
            break;
        }

        ++len;

        if(len >= sizeof(TEXT("TMP=")) - 1)
        {
            if(0 == ::memcmp(p, TEXT("TMP="), 4))
            {

                break;
            }
        }

    }
    return len;
}


bool get_env_value(::DWORD pid, const TCHAR* env_name, str::xtype& out)
{

    bool no_err{ false };
    do
    {
        if(0 == pid)
        {
            break;
        }

        if(nullptr == env_name)
        {
            break;
        }

        auto name_len = ::_tcsclen(env_name);
        if(-1 == name_len)
        {
            break;
        }

        if(env_name[name_len] != TEXT('='))
        {
            ++name_len;
        }


        ::HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if(NULL == hProcess)
        {
            break;
        }

        ::HANDLE hToken{ NULL };
        if(FALSE == ::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            ::CloseHandle(hProcess);
            break;
        }

        ::DWORD needed_size{ 0 };
        ::GetTokenInformation(hToken, TokenUser, NULL, 0, &needed_size);
        ::PTOKEN_USER pTokenUser = (::PTOKEN_USER)malloc(needed_size);
        if(FALSE == ::GetTokenInformation(hToken, TokenUser, pTokenUser, needed_size, &needed_size))
        {
            ::CloseHandle(hToken);
            ::CloseHandle(hProcess);
            ::free(pTokenUser);
            break;
        }

        void* environment = NULL;
        if(TRUE == ::CreateEnvironmentBlock(&environment, hToken, FALSE))
        {
            TCHAR* envs_value = (TCHAR*)environment;
            std::size_t len{ 0 };
            while(*envs_value)
            {
                len = ::_tcsclen(envs_value);
                if(len >= name_len)
                {
                    if(0 == ::memcmp(envs_value, env_name, name_len))
                    {
                        no_err = true;
                        out = envs_value + name_len;
                        break;
                    }
                }
                envs_value += len + 1;
            }
            ::DestroyEnvironmentBlock(environment);
        }
        else
        {
            log_message(common::log::level_enum::err, WLogText("failed to create en block {} ", ::GetLastError()));
        }

        ::free(pTokenUser);
        ::CloseHandle(hToken);
        ::CloseHandle(hProcess);

    } while(0);

    return no_err;
}

str::xtype get_user_temp()
{
    ::PROCESSENTRY32 pe32{ 0 };
    pe32.dwSize = sizeof(::PROCESSENTRY32);
    ::HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    str::xtype result;
    if(::Process32First(hSnapshot, &pe32))
    {
        do
        {
            if(_tcscmp(pe32.szExeFile, TEXT("explorer.exe")) == 0)
            {
                if(false == ::get_env_value(pe32.th32ProcessID, TEXT("TMP"), result))
                    log_message(common::log::level_enum::err, WLogText("failed to get temp {}", pe32.th32ProcessID));
                break;
            }
        } while(::Process32NextW(hSnapshot, &pe32));
    }
    ::CloseHandle(hSnapshot);
    return result;
}

bool GetProcessUsername(::DWORD pid, TCHAR* env_name, ::DWORD size)
{

    bool no_err{ false };
    do
    {
        ::HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if(NULL == hProcess)
        {
            break;
        }

        ::HANDLE hToken;
        if(FALSE == ::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            ::CloseHandle(hProcess);
            break;
        }

        ::DWORD needed_size = 0;
        ::GetTokenInformation(hToken, TokenUser, NULL, 0, &needed_size);
        ::PTOKEN_USER pTokenUser = (::PTOKEN_USER)malloc(needed_size);
        if(FALSE == GetTokenInformation(hToken, TokenUser, pTokenUser, needed_size, &needed_size))
        {
            ::CloseHandle(hToken);
            ::CloseHandle(hProcess);
            ::free(pTokenUser);
            break;
        }

        void* environment = NULL;
        if(::CreateEnvironmentBlock(&environment, hToken, FALSE))
        {
            LPWSTR envs_value = (LPWSTR)environment;
            int a = 0;
            while(*envs_value)
            {
                ++a;
                if(true)
                {

                }
                envs_value += wcslen(envs_value) + 1;
            }
            ::DestroyEnvironmentBlock(environment);
        }
        else
        {
            DWORD err = ::GetLastError();
        }

        ::free(pTokenUser);
        ::CloseHandle(hToken);
        ::CloseHandle(hProcess);


        //WCHAR domain[256];
        //DWORD domainSize = sizeof(domain) / sizeof(WCHAR);
        //DWORD usernameSize = size;
        //SID_NAME_USE sidType;

        //::free(pTokenUser);
        //::CloseHandle(hToken);
        //::CloseHandle(hProcess);
        no_err = true;

    } while(0);

    return no_err;
}

void ListExplorerUsers()
{
    ::PROCESSENTRY32 pe32{0};
    pe32.dwSize = sizeof(::PROCESSENTRY32);
    ::HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);


    while(1)
    {

        if(FALSE == ::Process32First(hSnapshot, &pe32))
            break;

        do
        {
            if(0 != ::wcscmp(pe32.szExeFile, L"explorer.exe"))
                break;

            WCHAR env_name[256] = { 0 };
            if(false == ::GetProcessUsername(pe32.th32ProcessID, env_name, 256))
                break;

            DWORD sessionId;
            if(FALSE == ::ProcessIdToSessionId(pe32.th32ProcessID, &sessionId))
                break;
                
            WCHAR sessionType[64] = TEXT("Local");
            ::WTS_CONNECTSTATE_CLASS state = WTS_CONNECTSTATE_CLASS::WTSActive;
            ::WTS_SESSION_INFO* pSessionInfo = NULL;
            DWORD count = 0;

            if(FALSE == ::WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &count))
                break;

            ::DWORD len{ 0 };
            for(DWORD i = 0; i < count; i++)
            {
                if(pSessionInfo[i].SessionId == sessionId)
                {
                    ::WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSConnectState, (LPWSTR*)&state, &len);
                    if(state == WTSActive && sessionId > 0)
                    {
                        wcscpy_s(sessionType, L"Remote (RDP)");
                    }
                    break;
                }
            }

            ::WTSFreeMemory(pSessionInfo);


        } while(::Process32NextW(hSnapshot, &pe32));

        break;
    }

    ::CloseHandle(hSnapshot);
}


bool get_file_hash(const std::filesystem::path& file_path, str::xtype& out)
{
    constexpr int buff_size = 1024;
    constexpr int md5_len = 16;
    ::DWORD dwStatus = 0;
    ::BOOL bResult = FALSE;
    ::HCRYPTPROV hProv = 0;
    ::HCRYPTHASH hHash = 0;
    ::HANDLE hFile = NULL;
    ::BYTE rgbFile[buff_size]{0};
    ::DWORD cbRead = 0;
    ::BYTE rgbHash[md5_len];
    ::DWORD cbHash = 0;
    constexpr char rgbDigits[] = "0123456789abcdef";
    // Logic to check usage goes here.
    hFile = ::CreateFile(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

    bool no_err{ false };
    do
    {
        if(INVALID_HANDLE_VALUE == hFile)
        {
            log_message(common::log::level_enum::err, WLogText("failed to open {}.{}", ::GetLastError(), file_path.wstring()));
            break;
        }

        if(FALSE == ::CryptAcquireContext(&hProv,
                                          NULL,
                                          NULL,
                                          PROV_RSA_FULL,
                                          CRYPT_VERIFYCONTEXT))
        {
            ::CloseHandle(hFile);
            log_message(common::log::level_enum::err, WLogText("CryptAcquireContext failed {}.{}", ::GetLastError(), file_path.wstring()));
            break;
        }

        if(FALSE == ::CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        {
            ::CloseHandle(hFile);
            ::CryptReleaseContext(hProv, 0);
            log_message(common::log::level_enum::err, WLogText("CryptCreateHash failed {}.{}", ::GetLastError(), file_path.wstring()));
            break;
        }

        no_err = true;
        while(bResult = ::ReadFile(hFile, rgbFile, buff_size, &cbRead, NULL))
        {
            if(0 == cbRead)
            {
                break;
            }

            if(FALSE == ::CryptHashData(hHash, rgbFile, cbRead, 0))
            {
                ::CryptReleaseContext(hProv, 0);
                ::CryptDestroyHash(hHash);
                ::CloseHandle(hFile);
                log_message(common::log::level_enum::err, WLogText("CryptHashData failed {}.{}", ::GetLastError(), file_path.wstring()));
                no_err = false;
                break;
            }
        }

        if(!no_err)
        {
            break;
        }

        no_err = false;

        if(!bResult)
        {
            ::CryptReleaseContext(hProv, 0);
            ::CryptDestroyHash(hHash);
            ::CloseHandle(hFile);
            log_message(common::log::level_enum::err, WLogText("ReadFile failed {}.{}", ::GetLastError(), file_path.wstring()));
            break;
        }

        cbHash = md5_len;
        if(::CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
        {
            out.resize(cbHash * 2);
            std::size_t pos{ 0 };
            for(::DWORD i = 0; i < cbHash; i++)
            {
                out[pos++] = rgbDigits[rgbHash[i] >> 4];
                out[pos++] = rgbDigits[rgbHash[i] & 0xf];
            }
            no_err = true;
        }
        else
        {
            log_message(common::log::level_enum::err, WLogText("CryptGetHashParam failed {}.{}", ::GetLastError(), file_path.wstring()));
        }

        ::CryptDestroyHash(hHash);
        ::CryptReleaseContext(hProv, 0);
        ::CloseHandle(hFile);

    } while(0);

    return no_err;
}


bool check_file_md5(const std::filesystem::path& file_path, const str::xtype& md5)
{
    str::xtype file_hash;
    if(get_file_hash(file_path, file_hash))
    {
        log_message(common::log::level_enum::info, WLogText("Hash {}.{}", file_hash, md5 == file_hash));
        return md5 == file_hash;
    }
    else
        return false;
}

bool create_and_test(const std::filesystem::path& dir_path, bool test)
{
    namespace fs = std::filesystem;
    namespace ch = std::chrono;

    bool no_err{ false };
    do
    {
        if(dir_path.empty())
        {
            break;
        }

        try
        {
            std::error_code ec;
            if(false == fs::exists(dir_path, ec))
            {
                log_message(common::log::level_enum::trace, WLogText_A("{} not exists. {}", dir_path.string(), ec.message()));
                auto copy = dir_path.generic_string();
                if(copy.back() == '/')
                {
                    copy.erase(copy.size() - 1);
                }

                if(false == fs::create_directories(copy, ec))
                {
                    log_message(common::log::level_enum::err, WLogText_A("failed to create directory {}.{}.{}", 
                                                                         ::GetLastError(), dir_path.string(), ec.message()));
                    break;
                }
            }

            if(test)
            {

                const auto now = ch::system_clock::now();
                const std::string filename = std::format("test_{0:%Y%m%d_%H%M%S}.txt", ch::floor<ch::seconds>(now));
                const fs::path file_path = dir_path / filename;

                {
                    std::ofstream ofs(file_path);
                    if(!ofs)
                    {
                        log_message(common::log::level_enum::err, WLogText_A("failed to create file {}.{}", ::GetLastError(), dir_path.string()));
                        break;
                    }
                    ofs << std::format("{0:%Y-%m-%d %H:%M:%S}", now);
                    ofs.close();
                }

                if(false == fs::remove(file_path, ec))
                {
                    log_message(common::log::level_enum::err, WLogText_A("failed to delete file {}.{}.{}",
                                                                         ::GetLastError(), dir_path.string(), ec.message()));
                    break;
                }
                no_err = true;
            }
        }
        catch(const std::exception& e)
        {
            log_message(common::log::level_enum::err, WLogText_A("{} exception: {}", dir_path.string(), e.what()));
        }

    } while(0);

    return no_err;
}

bool download_url_file(const str::xtype& url, const str::xtype& md5, str::xtype& out)
{
    log_message(common::log::level_enum::trace, WLogText_A("ready to do the download"));
    bool download_success{ false };
    std::filesystem::path store_path{ get_user_temp() };
    do
    {
        const TCHAR* pTemp{ nullptr };
        TCHAR temp_dir[MAX_PATH + 2]{ 0 };
        auto len = ::GetEnvironmentVariable(TEXT("temp"), temp_dir, MAX_PATH + 1);
        if(0 == len)
        {
            log_message(common::log::level_enum::err, WLogText_A("failed to get temp dir {}", ::GetLastError()));
            pTemp = TEXT("c:\\xixi_temp");
        }
        else
        {
            temp_dir[len] = TEXT('\0');
            pTemp = temp_dir;
        }

        if(store_path.empty())
        {
            store_path = TEXT("c:\\xixi_temp");
        }

        if(false == create_and_test(store_path, true))
        {
            break;
        }

        std::uint8_t wget_try_count{ 0 };
        store_path /= "XixiExam.exe";
        log_message(common::log::level_enum::trace, WLogText("url:{}  store:{}", url, store_path.wstring()));
        if(true == std::filesystem::exists(store_path))
        {
            log_message(common::log::level_enum::trace, WLogText_A("file already exists, initiating hash check."));
            if(check_file_md5(store_path, md5))
            {
                download_success = true;
                break;
            }
        }

        log_message(common::log::level_enum::trace, WLogText_A("begin download"));
        ::HRESULT download_err = ::URLDownloadToFile(NULL, url.c_str(), store_path.c_str(), NULL, NULL);
        if(download_err == S_OK)
        {
            download_success = check_file_md5(store_path, md5);
        }

        if(false == download_success)
        {
            auto last_err = ::GetLastError();
            download_success = std::filesystem::remove(store_path);
            log_message(common::log::level_enum::trace, WLogText("first download failed! {}.{:X}.{}",
                                                                 download_success, 
                                                                 static_cast<std::make_unsigned_t<decltype(download_err)>>(download_err),
                                                                 last_err));
        }
        else
        {
            log_message(common::log::level_enum::trace, WLogText("download success {}", store_path.wstring()));
            break;
        }

        {
            namespace osi = os::software::info;
            namespace osp = os::software::process;
            download_success = false;
            str::xtype dir_path = osi::app<osi::get::kDirPath>();
            auto wget_exe = dir_path += TEXT("wget.exe");
            os::software::process::execute execute_obj;
            str::xtype cmd = xfmt::format(TEXT("wget {} -t 0 -O {} -x"), url, store_path.wstring());
            if(false == execute_obj.create(wget_exe, cmd))
            {
                log_message(common::log::level_enum::err,
                            WLogText("final download attempt failed: process creation denied for {}", cmd));
                break;
            }

            osp::wait_opt opt;
            osp::execute_result_t result;
            do
            {
                result = execute_obj.wait_for_exit(opt);
                if(result.status == osp::execute_result_t::status_type_t::kFinish && result.exit_code == 0)
                {
                    if(check_file_md5(store_path, md5))
                    {
                        download_success = true;
                        log_message(common::log::level_enum::trace, WLogText("download success {}", store_path.wstring()));
                        break;
                    }
                    else
                    {
                        log_message(common::log::level_enum::trace, WLogText("failed to check {}", store_path.wstring()));
                        break;
                    }
                }

            } while(++wget_try_count < 3);
        }

    } while(0);

    if(false == download_success)
    {
        bool cleared = std::filesystem::remove(store_path);
        log_message(common::log::level_enum::trace, WLogText("final download attempt failed, file {}, check process", cleared));
    }
    else
    {
        out = store_path.wstring();
    }

    return download_success;
}

void on_update_success()
{
    ::KillTimer(gHwnd, TIMER_ID);
    ::SendMessage(gHprogress, PBM_SETPOS, 100, 0);
    ::Sleep(500);
    ::SetWindowText(gLabel, TEXT("安装已经完成，开始退出"));
    ::PostMessage(gHwnd, WM_QUIT, 0, 0);
}

void on_update_error()
{
    gUpdateError.store(true);
    ::KillTimer(gHwnd, TIMER_ID);
    ::SendMessage(gHprogress, PBM_SETPOS, 100, 0);
    ::SetWindowText(gLabel, TEXT("安装过程发生错误"));
}

namespace xixi
{
    struct exam_config
    {
        int EnableProxy{ 0 };
        std::string ServerAPIIP;
        std::string ServerAPIPort;
        std::string exitPwd;
        std::uint32_t HostServicePort{ 0 };
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(exam_config, EnableProxy, ServerAPIIP, ServerAPIPort, exitPwd, HostServicePort);
    };


    struct contract_config
    {
        std::string url;
        std::string version;
        std::string md5;
        std::string date;
        std::string ip;
        std::string new_install_dir;
        std::string old_install_dir;
        std::string force_operation; 
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(contract_config, url, version, md5, date, ip, new_install_dir, old_install_dir, force_operation);
    };


    struct update_config
    {
        str::xtype url;
        str::xtype version;
        str::xtype md5;
        str::xtype date;
        str::xtype ip;
        std::filesystem::path new_install_dir;
        std::filesystem::path old_install_dir;
        str::xtype force_operation; // "install" “uninstall” ""
    };


    void log_open_error(const std::string& file_path)
    {
        namespace fs = std::filesystem;
        const fs::path& path{ file_path };
        std::error_code ec;
        if(!fs::exists(path, ec))
        {
            log_message(common::log::level_enum::err, WLogText_A("file not exist: {} ({})", file_path, ec.message()));
            return;
        }

        if(fs::is_directory(path, ec))
        {
            log_message(common::log::level_enum::err, WLogText_A("path is directory: {}", file_path));
            return;
        }

        auto perms = fs::status(path, ec).permissions();
        if((perms & fs::perms::owner_read) == fs::perms::none)
        {
            log_message(common::log::level_enum::err, WLogText_A("no read permission: {}", file_path));
            return;
        }

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
        log_message(common::log::level_enum::err, WLogText_A("open {} failed {}: {}", file_path, err, msg));
        ::LocalFree(msg);
    }


    template<typename T>
    bool write_config_to_file(const std::filesystem::path& file_path, T& data)
    {
        bool no_err{ false };
        do
        {
            try
            {
                nlohmann::json json_obj = data;
                std::ofstream out(file_path, std::ios_base::trunc | std::ios_base::out);
                if(false == out.is_open())
                {
                    log_message(common::log::level_enum::debug, WLogText_A("Failed to open file: {}", file_path.generic_string()));
                    break;
                }

                out << json_obj.dump(4) << '\n';
                if(!out)
                {
                    log_message(common::log::level_enum::debug, WLogText_A("failed to write data: {}", ::GetLastError()));
                    break;
                }
                out.close();
            }
            catch(const std::exception& exception)
            {
                log_message(common::log::level_enum::debug, WLogText_A("failed to write, exception: {}", exception.what()));
                break;
            }

            no_err = true;

        } while(0);

        return no_err;
    }

    template<typename T>
    bool read_config_from_file(const std::filesystem::path& file_path, T& data)
    {
        bool no_err{ false };
        do
        {
            try
            {
                std::ifstream in(file_path, std::ios::in);
                if(false == in.is_open())
                {
                    log_message(common::log::level_enum::debug, WLogText_A("failed to open file: {}", file_path.generic_string()));
                    break;
                }

                nlohmann::json json_obj;
                in >> json_obj;
                data = json_obj.get<T>();
                in.close();
            }
            catch(const std::exception& exception)
            {
                log_message(common::log::level_enum::debug, WLogText_A("failed to read, exception: {}", exception.what()));
                break;
            }

            no_err = true;

        } while(0);

        return no_err;
    }


    std::optional<::DWORD> wait_exit(const TCHAR* p, const TCHAR* c, ::ULONG mask, bool show, bool wait)
    {
        p = p ? p : TEXT("");
        c = c ? c : TEXT("");
        log_message(common::log::level_enum::trace, WLogText("p=[{}] c=[{}]", p, c));
        ::SHELLEXECUTEINFO sei = { 0 };
        sei.cbSize = sizeof(::SHELLEXECUTEINFO);
        sei.lpVerb = TEXT("runas");
        sei.lpFile = p;
        sei.lpParameters = c;
        sei.fMask = mask;
        sei.nShow = show ? SW_SHOW : SW_HIDE;

        std::optional<::DWORD> ec{ std::nullopt };
        do
        {
            if(false == ::ShellExecuteEx(&sei))
            {
                log_message(common::log::level_enum::err,
                            WLogText("failed to open process {}.[{}][{}]", ::GetLastError(), p, c));
                break;
            }

            if(!wait)
            {
                ec = 1;
                break;
            }


            if(sei.hProcess == NULL)
            {
                log_message(common::log::level_enum::err, WLogText("invalid process {}.[{}][{}]", ::GetLastError(), p, c));
                break;
            }

            ::DWORD dwExitCode{ 0 };
            ::WaitForSingleObject(sei.hProcess, INFINITE);
            ::GetExitCodeProcess(sei.hProcess, &dwExitCode);
            ::CloseHandle(sei.hProcess);
            ec = dwExitCode;

        } while(0);

        return ec;
    }
}// end namespace xixi


xixi::contract_config gContract;

void open_exam_app(const xixi::update_config& update_config_obj, int& update_result_code)
{
    if(update_result_code >= 0)
    {
        constexpr auto param = TEXT("flag=update;");
#ifdef _DEBUG
        std::filesystem::path exam_exe = TEXT(R"(D:\ProjectWork\XiXiExam2\bin\debug\习习考试.exe)");
#else
        std::filesystem::path exam_exe = update_config_obj.new_install_dir / "习习考试.exe";
#endif
        log_message(common::log::level_enum::trace, WLogText("run [{}]", exam_exe.generic_wstring()));

        if(xixi::wait_exit(exam_exe.c_str(), param, 0, true, false))
        {
            log_message(common::log::level_enum::trace, WLogText("exam is opening"));
            update_result_code = __LINE__;
            on_update_success();
        }
        else
        {
            on_update_error();
            log_message(common::log::level_enum::trace, WLogText("failed to open exam"));
        }
    }
    else
    {
        on_update_error();
    }
}



namespace installed_info
{
    constexpr str::xview kDisplayVersion{ TEXT("DisplayVersion") };
    constexpr str::xview kUninstallString{ TEXT("UninstallString") };
    constexpr str::xview kInstallLocation{ TEXT("InstallLocation") };
    constexpr str::xview kInstallAppPath{ TEXT("Inno Setup: App Path") };

    constexpr str::xview kForceUninstall{ TEXT("uninstall") };
    constexpr str::xview kForceInstall{ TEXT("install") };
    constexpr str::xview kUninstallExeName{ TEXT("unins000.exe") };

    struct app_reg_info
    {
        str::xtype display_version{ TEXT("display_version") };
        str::xtype uninstall_string{ TEXT("uninstall_string") };
        str::xtype install_location{ TEXT("install_location") };
        str::xtype install_app_path{ TEXT("Inno Setup: App Path") };
    };

    struct install_decision
    {
        bool must_uninstall{ false };
        bool must_install{ false };
        bool skip_operation{ false };
    };
}

std::optional<installed_info::app_reg_info> get_installed_app_info()
{
    constexpr auto subkey = TEXT(R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{4D0C0095-90EA-4D43-98ED-603E54227EF3}_is1)");
    windows::regedit reg{ windows::regedit::open(HKEY_LOCAL_MACHINE, subkey, true) };
    if(false == reg.is_exist())
        return std::nullopt;

    installed_info::app_reg_info info;
    info.display_version = reg.get_string(installed_info::kDisplayVersion).value_or(TEXT(""));
    info.uninstall_string = reg.get_string(installed_info::kUninstallString).value_or(TEXT(""));
    info.install_location = reg.get_string(installed_info::kInstallLocation).value_or(TEXT(""));
    info.install_app_path = reg.get_string(installed_info::kInstallAppPath).value_or(TEXT(""));

    return info;
}

installed_info::install_decision determine_operation(const installed_info::app_reg_info& reg_info,
                                                     const str::xtype& version,
                                                     const str::xtype& force_operation)
{
    installed_info::install_decision decision;
    decision.must_uninstall = (str::xtype::npos != force_operation.find(installed_info::kForceUninstall));
    decision.must_install = decision.must_uninstall || (str::xtype::npos != force_operation.find(installed_info::kForceInstall));

    if(false == decision.must_install && reg_info.display_version == version)
    {
        log_message(common::log::level_enum::trace, WLogText("already installed {}", version));
        decision.skip_operation = true;
    }
    else if(reg_info.display_version != version)
    {
        decision.must_install = true; // 版本不同需要更新
    }

    return decision;
}

bool perform_uninstall(const installed_info::app_reg_info& reg_info,
                       const str::xtype& old_install_dir,
                       const str::xtype& update_app_path)
{
    str::xtype uninstall_exe_path;
    str::xtype dir;
    if(false == reg_info.uninstall_string.empty())
    {
        uninstall_exe_path = reg_info.uninstall_string;
    }
    else if(false == reg_info.install_location.empty())
    {
        dir = reg_info.install_location;
    }
    else if(false == reg_info.install_app_path.empty())
    {
        dir = reg_info.install_app_path + TEXT("\\");
    }
    else
    {
        dir = old_install_dir + TEXT("\\");
    }

    if(uninstall_exe_path.empty())
    {
        uninstall_exe_path = xfmt::format(TEXT("{}{}"), dir, installed_info::kUninstallExeName);
    }

    str::xtype silent_cmd = TEXT("/SILENT /VERYSILENT");
    str::xtype uninstall_cmd = xfmt::format(TEXT(R"({} /LOG="{}\log\inno_uninstall.log")"), silent_cmd, update_app_path);

    bool no_err{ false };
    auto exit_code = xixi::wait_exit(uninstall_exe_path.c_str(), uninstall_cmd.c_str(), SEE_MASK_NOCLOSEPROCESS, true, true);
    if(!exit_code)
    {
        log_message(common::log::level_enum::err, WLogText("uninstall failed during the open phase"));
    }
    else if(exit_code.value() != 0)
    {
        log_message(common::log::level_enum::err, WLogText("uninstall failed: {}", exit_code.value()));
    }
    else
    {
        log_message(common::log::level_enum::trace, WLogText("uninstall successful"));
        no_err = true;
    }
    return no_err;

}

bool perform_installation(const str::xtype& installer_path,
                          const str::xtype& new_install_dir,
                          const str::xtype& update_app_path)
{
    str::xtype silent_cmd = TEXT("/SILENT /VERYSILENT");
    str::xtype install_cmd = xfmt::format(TEXT(R"({} /DIR="{}" /LICENSEaccepted /LOG="{}\log\inno_install.log")"),
                                          silent_cmd,
                                          new_install_dir,
                                          update_app_path
    );

    bool no_err{ false };
    auto exit_code = xixi::wait_exit(installer_path.c_str(), install_cmd.c_str(), SEE_MASK_NOCLOSEPROCESS, true, true);
    if(!exit_code)
    {
        log_message(common::log::level_enum::err, WLogText("installation failed during the open phase "));
    }
    else if(exit_code.value() != 0)
    {
        log_message(common::log::level_enum::err, WLogText("installation failed: {}", exit_code.value()));
    }
    else
    {
        log_message(common::log::level_enum::trace, WLogText("installation successful"));
        no_err = true;
    }
    return no_err;
}

void do_update(std::uint8_t pos, const xixi::update_config& update_config_obj, int& out)
{
    Sleep(1000);
    bool success = false;
    const auto& [url, version, md5_ref, date, ip, new_install_dir, old_install_dir, force_operation] = update_config_obj;
    namespace osi = os::software::info;
    const str::xtype update_app_path = osi::app<osi::get::kDirPath>();

    do
    {
        try
        {
            auto reg_info_opt = get_installed_app_info();
            installed_info::install_decision decision;
            if(reg_info_opt)
            {
                decision = determine_operation(*reg_info_opt, version, force_operation);
            }
            else
            {
                decision.must_install = true;
                decision.must_uninstall = false;
                decision.skip_operation = false;
            }

            if(decision.skip_operation)
            {
                out = 0;
                success = true;
                break;
            }

            log_message(common::log::level_enum::trace, WLogText("p=[{}].[{}].[{}].[{}].[{}].", url, version, md5_ref, date, ip));

            str::xtype installer_path;
            if(decision.must_install)
            {
                if(false == create_and_test(new_install_dir, true))
                {
                    throw std::runtime_error("download test failed: insufficient permissions detected");
                }

                auto md5{ md5_ref };
                for(auto& ele : md5)
                {
                    ele = std::towlower(ele);
                }

                // http://192.168.16.11:3127/proxy/download/XixiExam?filename=xixiexam_student_update_3.1.10.15.exe
                if(false == download_url_file(url, md5, installer_path))
                {
                    throw std::runtime_error("download failed");
                }
            }

            if(decision.must_uninstall && reg_info_opt)
            {
                if(false == perform_uninstall(*reg_info_opt, old_install_dir, update_app_path))
                {
                    throw std::runtime_error("uninstall failed");
                }
            }

            if(decision.must_install)
            {
                if(false == perform_installation(installer_path, new_install_dir, update_app_path))
                {
                    throw std::runtime_error("installation failed");
                }
            }

            success = true;
            out = __LINE__;

        }
        catch(const std::exception& e)
        {
            log_message(common::log::level_enum::exception, WLogText_A("update exception: {}", e.what()));
            out = exit_code_t::kUpdateException;
        }

    } while(0);

    open_exam_app(update_config_obj, out);
}


#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define LABEL_HEIGHT 50

HFONT hFont = NULL;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static int progress = 0;

    switch(msg)
    {
    case WM_CREATE:
    {
        hFont = CreateFont(-30, 0, 0, 0, FW_BOLD,
                           FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS,
                           DEFAULT_QUALITY,
                           DEFAULT_PITCH | FF_DONTCARE,
                           TEXT("微软雅黑")
        );

        gLabel = CreateWindow(TEXT("STATIC"), TEXT("习习向上正在安装中......"),
                                WS_CHILD | WS_VISIBLE | SS_CENTER,
                                0, 0, 0, 0,
                                hwnd, NULL,
                                ((LPCREATESTRUCT)lParam)->hInstance,
                                NULL
        );

        gHprogress = CreateWindow(PROGRESS_CLASSW, NULL,
                                  WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                  0, 0, 0, 0,
                                  hwnd, NULL,
                                  ((LPCREATESTRUCT)lParam)->hInstance,
                                  NULL
        );

        ::SendMessage(gLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        ::SendMessage(gHprogress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        ::SendMessage(gHprogress, PBM_SETSTEP, 1, 0);
        ::SendMessage(gHprogress, PBM_SETBARCOLOR, 0, RGB(0, 255, 0));
        ::SendMessage(gHprogress, PBM_SETBKCOLOR, 0, RGB(255, 255, 255));

        auto hP = ::GetCurrentProcess();
        if(hP)
        {
            BOOL value = FALSE;
            ::SetUserObjectInformation(hP, UOI_TIMERPROC_EXCEPTION_SUPPRESSION, &value, sizeof(BOOL));
        }
        ::SetTimer(hwnd, TIMER_ID, 500, NULL);
        break;
    }
    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);

        int labelWidth = rc.right - rc.left - 20;
        int label_x = (rc.right - labelWidth) / 2;
        int label_y = rc.bottom / 2 - LABEL_HEIGHT - 20;
        SetWindowPos(gLabel, NULL,
                     label_x, label_y, labelWidth, LABEL_HEIGHT,
                     SWP_NOZORDER
        );

        int progressWidth = static_cast<int>(max((rc.right - rc.left) * 0.7, 200));
        int progressHeight = LABEL_HEIGHT - 10;
        int progress_x = (rc.right - progressWidth) / 2;
        int progress_y = rc.bottom / 2 + 35;
        SetWindowPos(gHprogress, NULL,
                     progress_x, progress_y, progressWidth, progressHeight,
                     SWP_NOZORDER
        );

        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);

        RECT windowRect;
        GetWindowRect(hwnd, &windowRect);
        int windowWidth = windowRect.right - windowRect.left;
        int windowHeight = windowRect.bottom - windowRect.top;

        int x = (screenWidth - windowWidth) / 2;
        int y = (screenHeight - windowHeight) / 2;

        ::SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE);

        break;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        if(false == gUpdateError.load())
        {
            ::SetTextColor(hdc, RGB(6, 176, 37));
        }
        else
        {
            ::SetTextColor(hdc, RGB(243, 22, 61));
        }
        ::SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)::GetStockObject(WHITE_BRUSH);
    }
    case WM_TIMER:
    {
        if(progress < 99)
        {
#ifdef _DEBUG
            progress += 9;
#else
            ++progress;
#endif
            ::SendMessage(gHprogress, PBM_SETPOS, progress, 0);
            //::SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        }
        else
        {
            ::KillTimer(hwnd, TIMER_ID);
        }
        break;
    }

    case WM_DESTROY:
    {
        ::KillTimer(hwnd, TIMER_ID);
        ::DeleteObject(hFont);
        ::PostQuitMessage(0);
        break;
    }

    case WM_TEST_COMMAND:
    {
        break;
    }

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance,
                    _In_opt_ HINSTANCE hPrevInstance,
                    _In_ LPWSTR lpCmdLine,
                    _In_ int nShowCmd)
{
    auto named_mutex = ::CreateMutex(NULL, TRUE, TEXT("Global\\XixiExam@Update"));
    if(NULL == named_mutex)
    {
        return exit_code_t::kCreateMutexError;
    }

#ifdef _DEBUG
    ::MessageBoxA(NULL, "更新程序运行在 DEBUG 模式", "通知", 0);
#endif

    log_message(common::log::level_enum::trace, WLogText("app run"));
    int argc{ 0 };
    auto argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if(NULL == argv)
    {
        log_message(common::log::level_enum::trace, WLogText("command invalid"));
        return exit_code_t::kCommandLineInvalid;
    }

    if(1 == argc)
    {
        log_message(common::log::level_enum::trace, WLogText("do not allow double-clicking to run"));
        return exit_code_t::kLaunchViaDoubleClick;
    }

    if(5 > argc)
    {
        log_message(common::log::level_enum::trace, WLogText("Received {} arguments (minimum required: 5)", argc));
        return exit_code_t::kArgumentCountBelowMin;
    }

    namespace osi = os::software::info;
    std::filesystem::path app_dir_path = osi::app<osi::get::kDirPath>();
    std::filesystem::path contract_file = app_dir_path / R"(contract.json)";
    std::uint8_t pos{ 0 };

    if(0 == ::memcmp(argv[0], TEXT("http"), 8))
    {
        pos = 0;
    }
    else
    {
        pos = 1;
    }

    xixi::update_config update_config_obj;
    if(xixi::read_config_from_file(contract_file, gContract))
    {
        update_config_obj.version = encode::string::utf8_to_utf16(gContract.version);
        update_config_obj.md5 = encode::string::utf8_to_utf16(gContract.md5);
        update_config_obj.date = encode::string::utf8_to_utf16(gContract.date);
        update_config_obj.ip = encode::string::utf8_to_utf16(gContract.ip);
        update_config_obj.url = xfmt::format(TEXT("http://{}:3127/{}"), update_config_obj.ip, encode::string::utf8_to_utf16(gContract.url));
        update_config_obj.new_install_dir = encode::string::utf8_to_utf16(gContract.new_install_dir);
        update_config_obj.old_install_dir = encode::string::utf8_to_utf16(gContract.old_install_dir);
        update_config_obj.force_operation = encode::string::utf8_to_utf16(gContract.force_operation);
    }
    else
    {
        update_config_obj.url = argv[pos++];
        update_config_obj.version = argv[pos++];
        update_config_obj.md5 = argv[pos++];
        update_config_obj.date = argv[pos++];
        update_config_obj.ip = argv[pos++];
        update_config_obj.new_install_dir = argv[argc - 1];
    }

    log_message(common::log::level_enum::trace, WLogText("app contract"));
    int update_thread_exit_code{ -3 };

    std::thread t{ do_update, pos, std::cref(update_config_obj), std::ref(update_thread_exit_code) };

    INITCOMMONCONTROLSEX icc = { sizeof(INITCOMMONCONTROLSEX), ICC_PROGRESS_CLASS };
    ::InitCommonControlsEx(&icc);

    constexpr auto class_name = TEXT("习习考试-自动安装窗口");

    WNDCLASSEXW wc = { };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = class_name;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_UPDATE));


    ::RegisterClassExW(&wc);

    gHwnd = ::CreateWindowEx(0,
                             class_name,
                             TEXT("习习考试-自动安装"),
                             WS_POPUP | WS_BORDER,
                             CW_USEDEFAULT, CW_USEDEFAULT,
                             800, 400,
                             NULL,
                             NULL,
                             hInstance,
                             NULL
    );

    ::ShowWindow(gHwnd, nShowCmd);
    ::UpdateWindow(gHwnd);

    MSG msg;
    while(::GetMessage(&msg, NULL, 0, 0))
    {
        ::TranslateMessage(&msg);
        ::DispatchMessage(&msg);
    }

    if(t.joinable())
        t.join();
    else
        log_message(common::log::level_enum::trace, WLogText("failed to join thread"));

    ::ReleaseMutex(named_mutex);
    ::CloseHandle(named_mutex);
    ::LocalFree(argv);
    ::Sleep(2000);

    log_message(common::log::level_enum::trace, WLogText("app exit"));
    return update_thread_exit_code;
}