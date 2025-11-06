#define WIN32_LEAN_AND_MEAN 
#include <windows.h>
#include <DbgHelp.h>
#include <thread>
#include "student_service.h"
#include "common/log/log.h"
#include "common/os-software/service-control-manager/scm.h"
#include "common/os-software/info/app.h"

#pragma comment(lib, "common-lib.lib")
#pragma comment(lib, "Dbghelp.lib")


template<typename T>
    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
static void log_message(int level, const T& message)
{
    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("service-cmd") };
    if(log)
    {
        log->write_log(level, message);
    }
}

::LONG WINAPI CsmmUnhandledExceptionFilter(_EXCEPTION_POINTERS* pExp)
{
    ::SYSTEMTIME SystemTime;
    ::GetSystemTime(&SystemTime);
    namespace osi = os::software::info;
    const str::xtype& app_dir = osi::app<osi::get::kDirPath>();
    const str::xtype& app_file_version = osi::app<osi::get::kFileVersion>();
    const auto& dump_path = WLogText("{}dump/{}-{}-{}-{}-{}-{}-{}.dmp", 
                                     app_dir, app_file_version,
                                     SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay,
                                     SystemTime.wHour + 8, SystemTime.wMinute, SystemTime.wSecond);

    ::CreateDirectory(app_dir.c_str(), NULL);

    ::HANDLE hFile = ::CreateFile(dump_path.c_str(), GENERIC_WRITE,
                                0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);

    if(INVALID_HANDLE_VALUE != hFile)
    {
       ::MINIDUMP_EXCEPTION_INFORMATION einfo;
        einfo.ThreadId = ::GetCurrentThreadId();
        einfo.ExceptionPointers = pExp;
        einfo.ClientPointers = FALSE;

        ::MiniDumpWriteDump(
            ::GetCurrentProcess(),
            ::GetCurrentProcessId(),
            hFile,
            MiniDumpWithFullMemory,
            &einfo,
            NULL,
            NULL);

        ::CloseHandle(hFile);
    }

    return EXCEPTION_EXECUTE_HANDLER;
}


int main(int argc, char* argv[])
{
    namespace osi = os::software::info;
    ::TCHAR temp_buffer[MAX_PATH];
    ::DWORD ret = ::GetCurrentDirectory(MAX_PATH, temp_buffer);
    str::xtype app_dir = osi::app<osi::get::kDirPath>();
    if(FALSE == ::SetCurrentDirectory(app_dir.c_str()))
    {
        log_message(1, WLogText("failed to set current directory: {}", ::GetLastError()));
    }

    common::log::manager::instance().set_log_dir(true, "log/");
    common::log::manager::instance().set_use_default_filename();

    if(argc > 1)
    {
        str::xtype command = ::GetCommandLine();
        try
        {
            os::software::service::scm scm{TEXT("")};
            if(str::xtype::npos != command.find(TEXT("--install")))
            {
                bool try_again{ false };
                int loop_count{ 0 };
                bool no_err{ false };
                const str::xtype& app_path = osi::app<osi::get::kPath>();
                do
                {
                    if(scm.is_exist(gKServiceName))
                    {
                        try_again = !scm.uninstall(gKServiceName);
                    }

                    if(try_again)
                    {
                        continue;
                    }

                    if(scm.install(app_path, gKServiceName, true))
                    {
                        try_again = (no_err = scm.start(gKServiceName), !no_err);
                    }

                } while(try_again && loop_count++ < 10);

                log_message(common::log::level_enum::trace, WLogText("install {}.{}.{}", no_err, loop_count, app_path));

                return no_err;
            }
            else if(str::xtype::npos != command.find(TEXT("--uninstall")))
            {
                return scm.uninstall(gKServiceName);
            }
            else if(str::xtype::npos != command.find(TEXT("--stop")))
            {
                return scm.stop(gKServiceName);
            }
            else if(str::xtype::npos != command.find(TEXT("--run")))
            {
                do
                {
                    decltype(scm)::status st{ decltype(scm)::status::kRunning };
                    if(scm.is_this_status(gKServiceName, st))
                    {
                        break;
                    }

                    if(scm.is_exist(gKServiceName))
                    {
                        scm.start(gKServiceName);
                    }

                } while(true);

                return 0;
            }
            else
            {
                WLogAC_EXCEPTION("err command:{}", command);
                return 1;
            }
        }
        catch(const std::system_error& e)
        {
            WLogAC_EXCEPTION_A("system error:{:s}", e.what());
            return 1;
        }
        catch(const std::runtime_error& e)
        {
            WLogAC_EXCEPTION_A("runtime error:{:s}", e.what());
            return 1;
        }
        catch(const std::exception& e)
        {
            WLogAC_EXCEPTION_A("error:{:s}", e.what());
            return 1;
        }
    }

    SERVICE_TABLE_ENTRY serviceTable[] = {
        { const_cast<wchar_t*>(gKServiceName), xixi_host_service::service_main },
        { nullptr, nullptr }
    };

    if(FALSE == ::StartServiceCtrlDispatcher(serviceTable))
    {
        log_message(1, WLogText("error starting service dispatcher: {}", ::GetLastError()));
        return 1;
    }

    return 0;
}