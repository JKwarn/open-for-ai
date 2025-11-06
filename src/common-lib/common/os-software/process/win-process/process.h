#pragma once
#include <windows.h>
#include <vector>
#include <functional>
#include <cstdint>
#include "string_define.h"


extern void ErrorText(PCTSTR lpszFunction);

namespace os::software::process
{
    struct redirect_handles
    {
        HANDLE childProcErrPipeW{ NULL };
        HANDLE childProcErrPipeR{ NULL };
        HANDLE childProcOutputPipeW{ NULL };
        HANDLE childProcOutputPipeR{ NULL };
        HANDLE childProcInputPipeW{ NULL };
        HANDLE childProcInputPipeR{ NULL };
    };

    struct redirect_result_t
    {
        enum flag_t
        {
            kError = 0,
            kSucced,
            kVoid,
        };
        using stream_t = std::vector<std::uint8_t>;
        using essence_t = std::vector<HANDLE>;

        flag_t mRedirectFlag{ flag_t::kVoid };
        stream_t mRedirectSteam;
    };

    struct process_info_t
    {
        using exit_code_t = std::make_signed<std::size_t>::type;
        enum class status_type_t :std::uint8_t
        {
            kException = 0,
            kFailed,
            kPending,
            kFinish,
            kNotCreate,
            kUnknown,
        };

        status_type_t mProcessStatus{ status_type_t::kUnknown };
        exit_code_t mExitCode{ 0 };
        PROCESS_INFORMATION mHandleID{ 0 };
    };

    struct execute_result_t
    {
        process_info_t mProcessInfo;
        redirect_result_t mRedirectResult;
        str::xtype mRunLogText;
    };

    struct zcp_opt
    {
        bool CreatePipeRedirect(str::xtype& logText);

        enum class executemode_t
        {
            kSyncExited = 0,
            kAsyncExited,
            kPromiseExited,
        };

        str::xtype mAppPath;
        str::xtype mAppParam;
        executemode_t mExecutemode{ executemode_t::kSyncExited };
        std::uint32_t mMaxWaitCount = INFINITE;
        DWORD mWaitTime = INFINITE;
        bool mNeedRedirect = false;
        redirect_handles mPipeHandles;
    };

    using async_callback_t = std::function<void(execute_result_t)>;
    execute_result_t Execute(zcp_opt& opt, const async_callback_t& callbcakFunction);



    /*
    #include <windows.h>
#include <string>
#include <memory>
#include <stdexcept>

class WindowsProcess {
public:
    WindowsProcess();
    ~WindowsProcess();
    WindowsProcess(const WindowsProcess&) = delete;
    WindowsProcess& operator=(const WindowsProcess&) = delete;

    void start(const std::wstring& applicationName, const std::wstring& commandLine = L"");

    DWORD waitForExit();

    DWORD getProcessId() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

class WindowsProcess::Impl {
public:
    Impl() : processHandle(NULL), processId(0) {}

    void startProcess(const std::wstring& appName, const std::wstring& cmdLine) {
        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        BOOL success = CreateProcessW(
            appName.empty() ? NULL : appName.c_str(),
            const_cast<LPWSTR>(cmdLine.empty() ? NULL : cmdLine.c_str()),
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (!success) {
            throw std::runtime_error("Failed to create process.");
        }

        processHandle = pi.hProcess;
        processId = pi.dwProcessId;

        CloseHandle(pi.hThread);
    }

    DWORD waitForProcess() const {
        if (processHandle == NULL) {
            throw std::runtime_error("Process not started.");
        }

        DWORD result = WaitForSingleObject(processHandle, INFINITE);
        if (result == WAIT_FAILED) {
            throw std::runtime_error("Failed to wait for process.");
        }

        DWORD exitCode;
        if (!GetExitCodeProcess(processHandle, &exitCode)) {
            throw std::runtime_error("Failed to get exit code.");
        }

        return exitCode;
    }

    DWORD getProcessId() const {
        return processId;
    }

    ~Impl() {
        if (processHandle != NULL) {
            CloseHandle(processHandle);
        }
    }

private:
    HANDLE processHandle;
    DWORD processId;
};


WindowsProcess::WindowsProcess() : pImpl(std::make_unique<Impl>()) {}

WindowsProcess::~WindowsProcess() = default;

void WindowsProcess::start(const std::wstring& applicationName, const std::wstring& commandLine) {
    pImpl->startProcess(applicationName, commandLine);
}

DWORD WindowsProcess::waitForExit() {
    return pImpl->waitForProcess();
}

DWORD WindowsProcess::getProcessId() const {
    return pImpl->getProcessId();
}


    */
}
