#include "process.h"
#include <strsafe.h>
#include <thread>
#include <memory>
#include <vector>
#include <string>
#include <sstream>
#include <cassert>
#include <iostream>
#include "log/log.h"
#include "fmt/fmt-pch.h"
#include "encode/string/string-encode.h"

#ifdef _UNICODE
#define _tmemcpy wmemcpy
#else
#define _tmemcpy memcpy
#endif // _UNICODE

void ErrorText(PCTSTR lpszFunction)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = ::GetLastError();

    ::FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    lpDisplayBuf = (LPVOID)::LocalAlloc(LMEM_ZEROINIT,
                                        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));

    ::StringCchPrintf((LPTSTR)lpDisplayBuf,
                      ::LocalSize(lpDisplayBuf) / sizeof(TCHAR),
                      TEXT("%s failed with error %d: %s"),
                      lpszFunction, dw, (LPCTSTR)lpMsgBuf);

    str::xtype logText{ (LPCTSTR)lpDisplayBuf };
    ::LocalFree(lpMsgBuf);
    ::LocalFree(lpDisplayBuf);
}

using status_t = os::software::process::process_info_t::status_type_t;
using execute_result_t = os::software::process::execute_result_t;

namespace os::software::process
{
    void DoExecute(const os::software::process::zcp_opt& opt, 
                   const os::software::process::async_callback_t& callbcakFunction, 
                   os::software::process::execute_result_t& execute_result);
    void DoExecute_Promise(os::software::process::zcp_opt opt,
                           os::software::process::async_callback_t callbcakFunction);

    bool PreExecute(str::xtype& logText, const zcp_opt& opt, STARTUPINFO& si, PROCESS_INFORMATION& pi, redirect_result_t::essence_t& handls);
    bool CreateProcessZ(str::xtype& logText, const zcp_opt& opt, STARTUPINFO& si, PROCESS_INFORMATION& pi);
    bool ResumeThreadZ(str::xtype& logText, const HANDLE& threadThread, std::size_t resumeCount = -1);
    void ReadFromRedirectPipe(redirect_result_t::essence_t essence, str::xtype appPath, redirect_result_t& outValue);
    status_t WaitSingleObjectFinish(str::xtype& logText, const HANDLE& object, const str::xtype& objDescription,
                                    DWORD singleWaitTime, uint8_t maxWaitCount);
}


bool os::software::process::zcp_opt::CreatePipeRedirect(str::xtype& logText)
{
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    bool noErr = false;
    do
    {
        if(!CreatePipe(&mPipeHandles.childProcOutputPipeR, &mPipeHandles.childProcOutputPipeW, &saAttr, 0))
            ErrorText(TEXT("StdoutRd CreatePipe"));

        if(!SetHandleInformation(mPipeHandles.childProcOutputPipeR, HANDLE_FLAG_INHERIT, 0))
            ErrorText(TEXT("Stdout SetHandleInformation"));

        if(!CreatePipe(&mPipeHandles.childProcInputPipeR, &mPipeHandles.childProcInputPipeW, &saAttr, 0))
            ErrorText(TEXT("Stdin CreatePipe"));

        if(!SetHandleInformation(mPipeHandles.childProcInputPipeW, HANDLE_FLAG_INHERIT, 0))
            ErrorText(TEXT("Stdin SetHandleInformation"));

        mPipeHandles.childProcErrPipeW = mPipeHandles.childProcOutputPipeW;
        mPipeHandles.childProcErrPipeR = mPipeHandles.childProcOutputPipeR;
        noErr = true;


        logText = WLogText("pipe = {} {} {} {} {} {}",
                           static_cast<void*>(mPipeHandles.childProcOutputPipeR), 
                           static_cast<void*>(mPipeHandles.childProcOutputPipeW),
                           static_cast<void*>(mPipeHandles.childProcInputPipeR), 
                           static_cast<void*>(mPipeHandles.childProcInputPipeW),
                           static_cast<void*>(mPipeHandles.childProcErrPipeR), 
                           static_cast<void*>(mPipeHandles.childProcErrPipeW)
        );
    } while(0);

    mNeedRedirect = noErr;
    return noErr;
}

void os::software::process::DoExecute(const os::software::process::zcp_opt& opt, 
                                      const os::software::process::async_callback_t& callbcakFunction,
                                      os::software::process::execute_result_t& outValue)
{
    using enumClass = process::process_info_t::status_type_t;

    STARTUPINFO si{ 0 };
    PROCESS_INFORMATION pi{ 0 };
    redirect_result_t::essence_t handles;
    execute_result_t ert;
    ert.mProcessInfo.mProcessStatus = enumClass::kNotCreate;
    str::xtype& logText = ert.mRunLogText;
    std::thread pipeReadThread;
    redirect_result_t redirect_result;


    do
    {
        if(!PreExecute(logText, opt, si, pi, handles))
        {
            break;
        }

        ert.mProcessInfo.mHandleID = pi;

        if(opt.mNeedRedirect)
        {
            redirect_result_t::essence_t essence;
            essence.push_back(opt.mPipeHandles.childProcOutputPipeR);
            essence.push_back(pi.hProcess);
            essence.push_back(pi.hThread);
            pipeReadThread = std::thread{ os::software::process::ReadFromRedirectPipe, essence, opt.mAppPath, std::ref(redirect_result) };
        }

        ert.mProcessInfo.mProcessStatus = process_info_t::status_type_t::kUnknown;
        DWORD waitTime = opt.mWaitTime;
        std::uint8_t waitCount = opt.mMaxWaitCount;
        if(!ResumeThreadZ(logText, pi.hThread))
        {
            break;
        }

        assert(pi.hProcess != NULL);

        enumClass processStatus = WaitSingleObjectFinish(logText, pi.hProcess, opt.mAppPath, waitTime, waitCount);
        DWORD exitCode{ 0 };
        if(pi.hProcess == NULL || 0 == ::GetExitCodeProcess(pi.hProcess, &exitCode))
        {
            logText = WLogText("{} 获取退出结果异常 {}.{}.{}", opt.mAppPath, static_cast<void*>(pi.hProcess), exitCode, ::GetLastError());
            ert.mProcessInfo.mProcessStatus = enumClass::kException;
        }
        else
        {
            ert.mProcessInfo.mProcessStatus = processStatus;
        }

        ert.mProcessInfo.mExitCode = exitCode;

    } while(0);

    DWORD temp;
    for(auto ele : handles)
    {
        if(!::GetHandleInformation(ele, &temp))
        {
            int pause = 1;
        }
        else
        {
            ::CloseHandle(ele);
        }
    }

    try
    {
        if(pipeReadThread.joinable())
        {
            pipeReadThread.join();
            ert.mRedirectResult = std::move(redirect_result);
        }
    }
    catch(const std::exception& e)
    {
        WLogAC_A("exception", common::log::exception, " {}.{} exception {}", static_cast<void*>(pi.hProcess), static_cast<void*>(pi.hThread), e.what());
        logText = WLogText("{}.{} exception", static_cast<void*>(pi.hProcess), static_cast<void*>(pi.hThread));
    }


    if(callbcakFunction)
    {
        callbcakFunction(std::move(ert));
    }
    else
    {
        outValue = ert;
    }
}

void os::software::process::DoExecute_Promise(os::software::process::zcp_opt opt, os::software::process::async_callback_t callbcakFunction)
{
    using enumClass = os::software::process::process_info_t::status_type_t;
    ::STARTUPINFO si{ 0 };
    ::PROCESS_INFORMATION pi{ 0 };
    redirect_result_t::essence_t handles;
    redirect_result_t redirect_result;
    execute_result_t execute_result;
    execute_result.mProcessInfo.mProcessStatus = enumClass::kNotCreate;
    str::xtype& logText = execute_result.mRunLogText;
    std::thread pipeReadThread;

    do
    {
        if(!PreExecute(logText, opt, si, pi, handles))
        {
            break;
        }

        if(opt.mNeedRedirect)
        {
            redirect_result_t::essence_t essence;
            essence.push_back(opt.mPipeHandles.childProcOutputPipeR);
            essence.push_back(pi.hProcess);
            essence.push_back(pi.hThread);
            pipeReadThread = std::thread{ os::software::process::ReadFromRedirectPipe, essence, opt.mAppPath, std::ref(redirect_result) };
        }

        execute_result.mProcessInfo.mProcessStatus = enumClass::kUnknown;
        DWORD waitTime = opt.mWaitTime;
        std::uint8_t waitCount = opt.mMaxWaitCount;
        if(!ResumeThreadZ(logText, pi.hThread))
        {
            break;
        }

        auto processStatus = WaitSingleObjectFinish(logText, pi.hProcess, opt.mAppPath, waitTime, waitCount);
        do
        {
            processStatus = WaitSingleObjectFinish(logText, pi.hProcess, opt.mAppPath, waitTime, waitCount);
        } while(enumClass::kPending == processStatus);

        DWORD exitCode{ 0 };
        if(pi.hProcess == NULL || 0 == ::GetExitCodeProcess(pi.hProcess, &exitCode))
        {
            logText = WLogText("{} 获取退出结果异常 {}.{}", opt.mAppPath, exitCode, ::GetLastError());
            execute_result.mProcessInfo.mProcessStatus = enumClass::kException;
        }
        else
        {
            execute_result.mProcessInfo.mProcessStatus = processStatus;
        }

        execute_result.mProcessInfo.mExitCode = exitCode;

    } while(0);

    DWORD temp;
    for(auto ele : handles)
    {
        if(!::GetHandleInformation(ele, &temp))
        {
            // tips
        }
        else
        {
            ::CloseHandle(ele);
        }
    }

    try
    {
        if(pipeReadThread.joinable())
        {
            pipeReadThread.join();
            execute_result.mRedirectResult = std::move(redirect_result);
        }
    }
    catch(const std::exception& e)
    {
        WLogAC_A("exception", common::log::exception, " {}.{} exception {}", static_cast<void*>(pi.hProcess), static_cast<void*>(pi.hThread), e.what());
        return;
    }

    if(callbcakFunction)
    {
        callbcakFunction(std::move(execute_result));
    }
}

bool os::software::process::PreExecute(str::xtype& logText, const zcp_opt& opt,
                                  STARTUPINFO& si, PROCESS_INFORMATION& pi,
                                  redirect_result_t::essence_t& handls)
{
    si.cb = sizeof(si);
    if(opt.mNeedRedirect)
    {
        si.hStdError = opt.mPipeHandles.childProcErrPipeW ? opt.mPipeHandles.childProcErrPipeW : 0;
        si.hStdOutput = opt.mPipeHandles.childProcOutputPipeW ? opt.mPipeHandles.childProcOutputPipeW : 0;
        si.hStdInput = opt.mPipeHandles.childProcInputPipeW ? opt.mPipeHandles.childProcInputPipeR : 0;
        si.dwFlags |= STARTF_USESTDHANDLES;
    }
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if(!CreateProcessZ(logText, opt, si, pi))
    {
        return false;
    }

    if(opt.mNeedRedirect)
    {
        handls.reserve(8);
        handls.push_back(pi.hProcess);
        handls.push_back(pi.hThread);
        handls.insert(handls.begin(), opt.mPipeHandles.childProcOutputPipeR);
        handls.insert(handls.begin(), opt.mPipeHandles.childProcInputPipeR);
        handls.insert(handls.begin(), opt.mPipeHandles.childProcErrPipeR);

        handls.insert(handls.begin(), opt.mPipeHandles.childProcErrPipeW);
        handls.insert(handls.begin(), opt.mPipeHandles.childProcInputPipeW);
        handls.insert(handls.begin(), opt.mPipeHandles.childProcOutputPipeW);
    }
    else
    {
        handls.push_back(pi.hProcess);
        handls.push_back(pi.hThread);
    }

    return true;
}

bool os::software::process::CreateProcessZ(str::xtype& logText, const zcp_opt& opt, STARTUPINFO& si, PROCESS_INFORMATION& pi)
{
    bool noErr = false;
    std::unique_ptr<TCHAR[]> appParamCopy = nullptr;
    do
    {
        try
        {
            auto len = opt.mAppParam.length() + 1;
            appParamCopy = std::make_unique<TCHAR[]>(2 * len);
            ::_tmemcpy(appParamCopy.get(), opt.mAppParam.c_str(), 2 * len);
            appParamCopy[len] = TEXT('\0');
            appParamCopy[2 * len - 1] = TEXT('\0');
        }
        catch(const std::exception& e)
        {
            const auto& u16 = encode::string::utf8_to_utf16(e.what());
            logText = WLogText("{} {} 未能完成前置步骤 {}", u16, opt.mAppPath, ::GetLastError());
            break;
        }

        DWORD createFlags = 0;
        if(opt.mNeedRedirect)
        {
            createFlags = CREATE_SUSPENDED;
        }

        BOOL createResult = ::CreateProcess(opt.mAppPath.c_str(),
                                            appParamCopy.get(),
                                            NULL, NULL,
                                            opt.mNeedRedirect ? TRUE : FALSE,
                                            createFlags,
                                            NULL, NULL,
                                            &si, &pi );

        if(createResult == 0)
        {
            logText = WLogText("{} 初始化失败 {}", opt.mAppPath, ::GetLastError());
            break;
        }
        if(pi.hProcess == NULL)
        {
            logText = WLogText("{} 未能分配正确标识 {}", opt.mAppPath, ::GetLastError());
            break;
        }

        noErr = true;
    } while(0);

    return noErr;
}

bool os::software::process::ResumeThreadZ(str::xtype& logText, const HANDLE& threadThread, std::size_t resumeCount)
{
    DWORD lastResumeResult = 0;
    do
    {
        lastResumeResult = ::ResumeThread(threadThread);
        if((DWORD)-1 == lastResumeResult)
        {
            logText = WLogText("未能恢复线程{}.{}", threadThread, ::GetLastError());
            break;
        }
    } while(lastResumeResult > 1 && (resumeCount > 0 ? --resumeCount > 0 : false));

    assert(!(lastResumeResult > 1));
    return !(lastResumeResult > 1);
}

void os::software::process::ReadFromRedirectPipe(redirect_result_t::essence_t essence, str::xtype appPath, redirect_result_t& outValue)
{
    using type = process::redirect_result_t;
    using enumClass = type::flag_t;
    enumClass flags = enumClass::kSucced;
    std::vector<uint8_t> byteBuff;
    auto injectTextToResult = [&byteBuff, &flags](str::xtype& msgText, enumClass newflags)
        {
            byteBuff.clear();
            auto memSize = (msgText.length() + 1) * sizeof(TCHAR);
            if(byteBuff.size() <= memSize)
            {
                byteBuff.reserve(memSize);
            }

            auto len = msgText.length() * sizeof(TCHAR);

            for(size_t i = 0; i < len; i++)
            {
                byteBuff.push_back(*((std::uint8_t*)(msgText.data()) + i));
            }
            byteBuff.push_back(TEXT('\0'));
            flags = newflags;
        };

    str::xtype errMsg;
    DWORD temp;
    auto size = essence.size();
    for(size_t i = 0; i < size; i++)
    {
        if(!::GetHandleInformation(essence[i], &temp))
        {
            if(errMsg.empty())
            {
                errMsg = WLogText("pipe 句柄无效 {}.{}.{}", essence[i], i, ::GetLastError());
            }
            else
            {
                errMsg.append(WLogText("{}.{}.{}", essence[i], i, ::GetLastError()));
            }
        }
    };


    HANDLE readHandle = NULL;
    HANDLE processHanlde = NULL;
    HANDLE threadHanlde = NULL;

    if(FALSE == errMsg.empty())
    {
        injectTextToResult(errMsg, enumClass::kError);
        goto _WORK_DONE_;
    }

    readHandle = essence[0];
    processHanlde = essence[1];
    threadHanlde = essence[2];

    do
    {
        DWORD currentRead = 0;
        DWORD totalRead = 0;
        constexpr auto BUFSIZE = 1024;
        uint8_t readBuff[BUFSIZE]{ 0 };
        BOOL bSuccess = FALSE;
        DWORD resumeCount = 0;

        if(!ResumeThreadZ(errMsg, threadHanlde))
        {
            injectTextToResult(errMsg, enumClass::kError);
            break;
        }

        for(;;)
        {
            bSuccess = ::ReadFile(readHandle, readBuff, BUFSIZE, &currentRead, NULL);
            if(!bSuccess)
            {
                if(ERROR_IO_PENDING == ::GetLastError())
                {
                    continue;
                }
                else if(ERROR_BROKEN_PIPE == ::GetLastError())
                {
                    break;
                }
            }

            if(!bSuccess || currentRead == 0)
            {
                errMsg = WLogText("pipe 读取错误 {}.{}", readHandle, ::GetLastError());
                injectTextToResult(errMsg, enumClass::kError);
                break;
            }

            totalRead += currentRead;
            byteBuff.reserve(totalRead);

            for(size_t i = 0; i < currentRead; i++)
            {
                byteBuff.push_back(readBuff[i]);
            }
            ::memset(readBuff, 0, BUFSIZE);
        }

    } while(0);

_WORK_DONE_:
    byteBuff.shrink_to_fit();
    outValue.mRedirectFlag = flags;
    outValue.mRedirectSteam = std::move(byteBuff);
}

status_t os::software::process::WaitSingleObjectFinish(str::xtype& logText, const HANDLE& object,
                                                       const str::xtype& objDescription, DWORD singleWaitTime, uint8_t maxWaitCount)
{
    using enumClass = process::process_info_t::status_type_t;
    DWORD waitResult = 0;
    auto waitCount = 0;
    std::vector<DWORD> failedCount{ maxWaitCount };
    do
    {
        waitResult = ::WaitForSingleObject(object, singleWaitTime);
        switch(waitResult)
        {
        case WAIT_OBJECT_0:
            waitCount = maxWaitCount;
            break;
        case WAIT_FAILED:
            maxWaitCount > 0 ? failedCount[waitCount] = ::GetLastError() : 0;
            break;
        default:
            break;
        }

    } while(++waitCount < maxWaitCount);

    auto ret{ enumClass::kException };
    if(WAIT_OBJECT_0 == waitResult)
    {
        ret = enumClass::kFinish;
    }
    else if(WAIT_TIMEOUT == waitResult)
    {
        logText = WLogText("{} 已经超过最大等待次数[{}.{}]，仍未结束", objDescription.c_str(), maxWaitCount, singleWaitTime);
        ret = enumClass::kPending;
    }
    else if(WAIT_FAILED == waitResult)
    {
        logText = WLogText("{} 等待执行结果失败 {}", objDescription, ::GetLastError());
        std::ostringstream oss;
        std::print(oss, " {} ", failedCount);
        logText += encode::string::utf8_to_utf16(oss.str());

        ret = enumClass::kFailed;
    }

    return ret;
}


execute_result_t os::software::process::Execute(process::zcp_opt& opt, const process::async_callback_t& callbcakFunction)
{
    execute_result_t result;
    str::xtype& logText = result.mRunLogText;

    if(opt.mNeedRedirect)
    {
        if(false == opt.CreatePipeRedirect(logText))
        {
            return result;
        }
    }

    switch(opt.mExecutemode)
    {
    case process::zcp_opt::executemode_t::kSyncExited:
        os::software::process::DoExecute(opt, nullptr, result);
        break;
    case process::zcp_opt::executemode_t::kAsyncExited:
    case process::zcp_opt::executemode_t::kPromiseExited:
        if(!callbcakFunction)
        {
            logText = WLogText("{} 想要以 {} 执行，但是没有提供回调", opt.mAppPath, static_cast<int>(opt.mExecutemode));
        }
        else
        {
            result.mProcessInfo.mProcessStatus = process::process_info_t::status_type_t::kPending;
            if(opt.mExecutemode == process::zcp_opt::executemode_t::kPromiseExited)
            {
                os::software::process::DoExecute(opt, nullptr, result);
                if(result.mProcessInfo.mProcessStatus == process::process_info_t::status_type_t::kPending)
                {
                    uint32_t temp = 0;
                    ::TerminateProcess(result.mProcessInfo.mHandleID.hProcess, temp);
                    auto optCopy = opt;
                    str::xtype tempLogText;
                    if(!optCopy.CreatePipeRedirect(tempLogText))
                    {
                        result.mRunLogText.append(std::move(tempLogText));
                    }
                    else
                    {
                        std::thread(os::software::process::DoExecute_Promise, optCopy, callbcakFunction).detach();
                    }
                }
            }
            else
            {
                os::software::process::execute_result_t temp{};
                std::thread{ os::software::process::DoExecute, std::cref(opt), std::cref(callbcakFunction), std::ref(temp) }.detach();
            }
        }
        break;
    default:
        logText = WLogText("{} 不知道以什么方式执行 {}", opt.mAppPath, static_cast<int>(opt.mExecutemode));
        break;
    }

    return result;
}

#ifdef _tmemcpy
#undef _tmemcpy
#endif