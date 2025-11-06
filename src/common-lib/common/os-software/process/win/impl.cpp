#pragma once
#ifndef _COMMON_OS_SOFTWARE_PROCESS_WIN_IMPL_H_
#define _COMMON_OS_SOFTWARE_PROCESS_WIN_IMPL_H_

#include <windows.h>
#include <strsafe.h>
#include <thread>
#include <memory>
#include <vector>
#include <string>
#include <sstream>
#include <cassert>
#include <span>
#include <iostream>
#include <format>

#include "common/log/log.h"
#include "common/log/logger_help.h"
#include "common/fmt/fmt-pch.h"
#include "common/encode/string/string-encode.h"
#include "process.h"

//
//// 用于日志记录
//template<typename T>
//    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
//static void log_message(int level, const T& message)
//{
//    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("info") };
//    if(log)
//    {
//        log->write_log(level, message);
//    }
//}

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

    bool create_redirect_pipe(common::log::logger_help& logger, ::STARTUPINFO& out)
    {
        ::SECURITY_ATTRIBUTES security_attr;
        security_attr.nLength = sizeof(::SECURITY_ATTRIBUTES);
        security_attr.bInheritHandle = TRUE;
        security_attr.lpSecurityDescriptor = NULL;

        bool no_err{true};
        std::vector<::HANDLE> pipes{ 4, NULL };
        do
        {
            //if(!CreatePipe(&out.childProcOutputPipeR, &out.childProcOutputPipeW, &security_attr, 0))
            //    ErrorText(TEXT("StdoutRd CreatePipe"));

            //if(!SetHandleInformation(out.childProcOutputPipeR, HANDLE_FLAG_INHERIT, 0))
            //    ErrorText(TEXT("Stdout SetHandleInformation"));

            //if(!CreatePipe(&out.childProcInputPipeR, &out.childProcInputPipeW, &security_attr, 0))
            //    ErrorText(TEXT("Stdin CreatePipe"));

            //if(!SetHandleInformation(out.childProcInputPipeW, HANDLE_FLAG_INHERIT, 0))
            //    ErrorText(TEXT("Stdin SetHandleInformation"));

            //::BOOL create_result = ::CreatePipe(&pipes[0], &pipes[1], &security_attr, 0);
            //if(FALSE == create_result)
            //{
            //    logger.log_message(common::log::level_enum::info, WLogText("failed to create pipe {}", ::GetLastError()));
            //    break;
            //}

            ::BOOL create_result{ TRUE };
            for(std::size_t i = 0; i < 4;)
            {
                create_result = ::CreatePipe(&pipes[i], &pipes[i+1], &security_attr, 0);
                if(FALSE == create_result)
                {
                    no_err = false;
                    logger.log_message(common::log::level_enum::err, WLogText("{} failed to create pipe {}", i, ::GetLastError()));
                    break;
                }
                i += 2;
            }

            if(!no_err)
            {
                break;
            }


            out.hStdError = pipes[1];
            out.hStdOutput = pipes[3];
            out.hStdInput = pipes[3];
            out.dwFlags |= STARTF_USESTDHANDLES;
        } while(0);

        logger.log_message(common::log::level_enum::debug, WLogText("pipes={:n}", pipes));

        return no_err;
    }


    process::execute_result_t::status_type_t
    wait_single_object_finish(common::log::logger_help& logger, const ::HANDLE object,
                              str::xtype description, ::DWORD wait_time_per, std::uint8_t max_wait_count)
    {
        using enumClass = process::execute_result_t::status_type_t;
        ::DWORD wait_result{ 0 };
        auto wait_count{0};
        std::vector<::DWORD> failed;
        max_wait_count > 0 ? failed.resize(max_wait_count), 1 : 0;
        do
        {
            wait_result = ::WaitForSingleObject(object, wait_time_per);
            switch(wait_result)
            {
            case WAIT_OBJECT_0:
                wait_count = max_wait_count;
                break;
            case WAIT_FAILED:
                max_wait_count > 0 ? failed[wait_count] = ::GetLastError() : 0;
                break;
            default:
                break;
            }

        } while(++wait_count < max_wait_count);

        auto ret{ enumClass::kException };
        if(WAIT_OBJECT_0 == wait_result)
        {
            ret = enumClass::kFinish;
        }
        else if(WAIT_TIMEOUT == wait_result)
        {
            logger.log_message(common::log::level_enum::info,
                               WLogText("{} max wait attempts [{}.{}] exceeded, process still ongoing",
                                        description, max_wait_count, wait_time_per));
            ret = enumClass::kStilActive;
        }
        else if(WAIT_FAILED == wait_result)
        {
            logger.log_message(common::log::level_enum::info,
                               WLogText("failed to wait for the {}.{:n}.{} execution result", 
                                        description, failed,::GetLastError()));
            ret = enumClass::kFailed;
        }

        return ret;
    }

}

namespace os::software::process
{
    class execute::impl : public common::log::logger_help
    {
    public:
        impl();
        impl(const str::xtype app_name, const str::xtype cmd_line);
        ~impl();

        bool create(bool suspended, bool redirect);
        bool create(const str::xtype& app_name, const str::xtype& cmd_line, bool suspended, bool redirect);

        void reset();

        bool can_it_wait(execute_result_t& execute_result, const wait_opt& opt);
        void do_wait(const wait_opt& opt, execute_result_t* out);
        execute_result_t wait_for_exit(const wait_opt& opt);
        void read_redirect_pipe();
        bool resume_process(std::size_t resumeCount = -1);
        std::uint64_t get_process_id() const;

    private:
        class resources;
        std::shared_ptr<resources> mResources;
        bool mWaitFlag;
    };
}


namespace os::software::process
{
    class execute::impl::resources
    {
    public:
        explicit resources(const str::xtype& app_name,
                           const str::xtype& app_cmd_line);
        ~resources();
        resources(const resources&) = default;
        resources& operator=(const resources&) = delete;


        using process_info_t = ::PROCESS_INFORMATION;
        using startup_info_t = ::STARTUPINFO;

        const auto& get_process_info() const { return mProcessInfo; }
        const auto& get_process_handle() const { return mProcessInfo.hProcess; }
        const auto& get_thread_handle() const { return mProcessInfo.hThread; }
        const auto& get_startup_info() const { return mStartupInfo; }
        const auto& get_redirect_handle() const { return mStartupInfo.hStdOutput; }
        const auto& get_redirect_result() const { return mRedirectResult; }
        const auto& get_app_name() const { return mAppName; }
        const auto& get_app_cmd_line() const { return mAppCmdLine; }

        void set_process_info(process_info_t&& process_info) {mProcessInfo = process_info;}
        void set_startup_info(startup_info_t&& startup_info) {mStartupInfo = startup_info;}
        void set_redirect_result(redirect_result_t&& redirect_result) {mRedirectResult = redirect_result;}
        void set_redirect_result(const redirect_result_t::flag_t& flag, redirect_result_t::stream_t&& stream);
        void set_app_name(const str::xtype& app_name) {mAppName = app_name;}
        void set_app_cmd_line(const str::xtype& app_cmd_line) {mAppCmdLine = app_cmd_line;}

        bool valid() const;

        str::xtype to_string() const;

        void clear();

        static void deleter(resources* ptr);
    private:
        process_info_t mProcessInfo;
        startup_info_t mStartupInfo;
        redirect_result_t mRedirectResult;
        str::xtype mAppName;
        str::xtype mAppCmdLine;
    };

}


namespace os::software::process
{
    execute::impl::resources::resources(const str::xtype& app_name,
                                        const str::xtype& app_cmd_line)
        :
        mProcessInfo{0},
        mStartupInfo{0},
        mAppName{ app_name },
        mAppCmdLine{ app_cmd_line }
    {
    }

    execute::impl::resources::~resources()
    {
        mProcessInfo={ 0 };
        mStartupInfo={ 0 };
        mAppName.clear();
        mAppCmdLine.clear();
    }

    void execute::impl::resources::set_redirect_result(const redirect_result_t::flag_t& flag, 
                                                       redirect_result_t::stream_t&& stream)
    {
        mRedirectResult.flag = flag;
        if(mRedirectResult.flag == redirect_result_t::flag_t::kSucced)
        {
            stream.shrink_to_fit();
            mRedirectResult.stream = stream;
        }
    }


    bool execute::impl::resources::valid() const
    {
        return NULL != mProcessInfo.hProcess && NULL != mProcessInfo.hThread;
    }


    str::xtype execute::impl::resources::to_string() const
    {
        return std::format(TEXT("process_info: {}.{}.{}.{}, ")
                           TEXT("redirect_result: {}, ")
                           TEXT("app_name: {}, app_cmd_line: {} }}"),
                           static_cast<const void*>(mProcessInfo.hProcess), mProcessInfo.dwProcessId,
                           static_cast<const void*>(mProcessInfo.hThread), mProcessInfo.dwThreadId,
                           static_cast<int>(mRedirectResult.flag),
                           mAppName,
                           mAppCmdLine);
    }

    void execute::impl::resources::clear()
    {
        std::vector< std::reference_wrapper<::HANDLE>> handles{ mProcessInfo.hProcess, mProcessInfo.hThread, 
                                                                mStartupInfo.hStdError, mStartupInfo.hStdInput, mStartupInfo.hStdOutput};
        ::DWORD temp_obj;
        for(auto& ele : handles)
        {
            if(::GetHandleInformation(ele, &temp_obj))
            {
                ::CloseHandle(ele);
            }
            else
            {
                int pause = 1;
            }
            ele.get() = nullptr;
        }

        if(mProcessInfo.hProcess == nullptr)
        {
            mProcessInfo.dwProcessId = 0;
        }

        if(mProcessInfo.hThread == nullptr)
        {
            mProcessInfo.dwThreadId = 0;
        }

    }

    void execute::impl::resources::deleter(resources* ptr)
    {
        if(nullptr == ptr)
            return;

        if(ptr->mProcessInfo.hProcess != nullptr)
        {
            ::CloseHandle(ptr->mProcessInfo.hProcess);
            ptr->mProcessInfo.hProcess = nullptr;
            ptr->mProcessInfo.dwProcessId = 0;

        }

        if(ptr->mProcessInfo.hThread != nullptr)
        {
            ::CloseHandle(ptr->mProcessInfo.hThread);
            ptr->mProcessInfo.hThread = nullptr;
            ptr->mProcessInfo.dwThreadId = 0;
        }

        delete ptr;
    }

    //process::impl::resources::operator bool() const
    //{
    //    return true
    //}
}


namespace os::software::process
{
    execute::impl::impl() : impl(TEXT(""), TEXT(""))
    {
    }

    execute::impl::impl(const str::xtype app_name, const str::xtype cmd_line)
        :logger_help{ "process" },
        mResources{ new resources(app_name, cmd_line) },
        mWaitFlag{ false }
    {
    }

        
    //    mProcessInfo{ 0 }, mStartupInfo{ 0 }, mAppName(app_name), mAppCmdLine(cmd_line)
    //{
    //}

    execute::impl::~impl()
    {
    }

    bool execute::impl::create(bool suspended, bool redirect)
    {
        return create(mResources->get_app_name(), mResources->get_app_cmd_line(), suspended, redirect);
    }

    bool execute::impl::create(const str::xtype& app_name, const str::xtype& cmd_line, bool suspended, bool redirect)
    {
        log_message(common::log::level_enum::trace, "create");
        bool no_err = false;
        do
        {
            resources::startup_info_t startup_info_copy{0};
            resources::process_info_t process_info_copy{0};

            startup_info_copy.cb = sizeof(startup_info_copy);

            if(redirect && !create_redirect_pipe(*this, startup_info_copy))
            {
                log_message(common::log::level_enum::info, WLogText("failed to create {}.{}", app_name, cmd_line));
                break;
            }

            startup_info_copy.dwFlags |= STARTF_USESHOWWINDOW;
            startup_info_copy.wShowWindow = SW_HIDE;

            ::BOOL success = ::CreateProcess(app_name.empty() ? NULL : app_name.c_str(),
                                             const_cast<LPTSTR>(cmd_line.empty() ? NULL : cmd_line.c_str()),
                                             NULL, NULL,
                                             redirect ? TRUE : FALSE,
                                             suspended ? CREATE_SUSPENDED : 0,
                                             NULL, NULL,
                                             &startup_info_copy, &process_info_copy
            );

            if(FALSE == success)
            {
                log_message(common::log::level_enum::info, WLogText("failed to create {}.{}.{}", app_name, cmd_line, ::GetLastError()));
                break;
            }

            if(NULL == process_info_copy.hProcess)
            {
                log_message(common::log::level_enum::info, WLogText("failed to create {}.{}.{}", app_name, cmd_line, ::GetLastError()));
                break;
            }

            no_err = true;

            if(!mResources)
            {
                mResources = std::make_shared<resources>(app_name, cmd_line);
            }

            mResources->set_startup_info(std::move(startup_info_copy));
            mResources->set_process_info(std::move(process_info_copy));

            if(mResources->get_app_name().empty())
            {
                mResources->set_app_name(app_name);
            }

            if(mResources->get_app_cmd_line().empty())
            {
                mResources->set_app_cmd_line(cmd_line);
            }

        } while(0);

        return no_err;
    }


    void execute::impl::reset()
    {
        if(mResources)
        {
            mResources.reset();
        }
        mWaitFlag = false;
    }

    bool execute::impl::can_it_wait(execute_result_t& execute_result, const wait_opt& opt)
    {
        log_message(common::log::level_enum::trace, "check");

        if(mWaitFlag)
        {
            execute_result.status = execute_result_t::status_type_t::kException;
            return true;
        }

        std::thread read_pipe_thread;
        do
        {
            if(false == mResources->valid())
            {
                execute_result.status = execute_result_t::status_type_t::kNotCreate;
                log_message(common::log::level_enum::info, WLogText("failed to check, {}", mResources->to_string()));
                break;
            }

            if(opt.need_redirect)
            {
                read_pipe_thread = std::thread{ &impl::read_redirect_pipe, this };
            }

            if(false == resume_process())
            {
                execute_result.status = execute_result_t::status_type_t::kStilActive;
                log_message(common::log::level_enum::info, WLogText("failed to check, can not resume {}", mResources->to_string()));
                break;
            }

            mWaitFlag = true;

            //auto wait_func = [](process::impl obj) {
            //    execute_result.status = wait_single_object_finish(obj,
            //        obj.log_message .hThread, mAppName, opt.wait_time_per, opt.max_wait_count);
            //    };
        

            //execute_result.status = wait_single_object_finish(*this, 
            //                                                  mProcessInfo.hThread, mAppName, opt.wait_time_per, opt.max_wait_count);
            //if(opt.execute_mode == wait_opt::execute_mode_t::kSyncExited)
            //{
            //    
            //}

            //::DWORD exitCode;
            //if(!::GetExitCodeProcess(mProcessInfo.hProcess, &exitCode))
            //{
            //    throw std::runtime_error("failed to get exit code.");
            //}

        } while(0);

        return mWaitFlag;

        //if(read_pipe_thread.joinable())
        //{

        //    read_pipe_thread.join(); 
        //    read_pipe_thread.detach();
        //}

        //execute_result.redirect = mRedirectResult;
        //return execute_result;
    }

    void execute::impl::do_wait(const wait_opt& opt, execute_result_t* out)
    {
        execute_result_t execute_result;
        do
        {
            execute_result.status = wait_single_object_finish(*this, mResources->get_thread_handle(),
                mResources->get_app_name(), opt.wait_time_per, opt.max_wait_count);

            if(execute_result_t::status_type_t::kFinish != execute_result.status)
            {
                break;
            }

            ::DWORD exit_code;
            auto no_err = ::GetExitCodeProcess(mResources->get_process_handle(), &exit_code);
            if(FALSE == no_err)
            {
                log_message(common::log::level_enum::info, WLogText("failed to get {}.{}.{}", no_err,
                    static_cast<int>(execute_result.status),
                    mResources->to_string(), ::GetLastError()));
                execute_result.status = execute_result_t::status_type_t::kException;
                break;
            }

            execute_result.exit_code = exit_code;
            mResources->clear();

        } while(0);

        if(opt.callback)
        {
            opt.callback(std::move(execute_result));
        }
        else if(out)
        {
            *out = std::move(execute_result);
        }
    }

    execute_result_t execute::impl::wait_for_exit(const wait_opt& opt)
    {
        execute_result_t execute_result;
        if(can_it_wait(execute_result, opt))
        {
            if(opt.callback)
            {
                std::thread(&impl::do_wait, std::move(*this), opt, nullptr).detach();
            }
            else
                do_wait(opt, &execute_result);
        }

        return execute_result;
    }


    void execute::impl::read_redirect_pipe()
    {
        using enumClass = redirect_result_t::flag_t;
        using stream_t = redirect_result_t::stream_t;
        enumClass flag_obj{ enumClass::kSucced };
        stream_t stream_obj;
        do
        {
            ::HANDLE read_handle{ mResources->get_redirect_handle() };
            ::DWORD handle_flag{ 0 };
            if(FALSE == ::GetHandleInformation(read_handle, &handle_flag))
            {
                log_message(common::log::level_enum::info, WLogText_A("failed to read, invalid {}.{}", read_handle, ::GetLastError()));
                break;
            }

            ::DWORD this_read{ 0 };
            std::size_t total_read {0};
            constexpr std::uint32_t buff_size{ 1024 };
            std::uint8_t buff[buff_size]{ 0 };
            std::span<std::uint8_t> buff_span(buff, buff_size);
            ::BOOL no_err{ FALSE };

            //if(false == resume_process())
            //{
            //    flag_obj = enumClass::kError;
            //    break;
            //}

            for(;;)
            {
                no_err = ::ReadFile(read_handle, buff, buff_size, &this_read, NULL);
                if(FALSE == no_err || this_read == 0)
                {
                    auto why = ::GetLastError();
                    if(ERROR_IO_PENDING == why)
                    {
                        continue;
                    }
                    else if(ERROR_BROKEN_PIPE == why)
                    {
                        break;
                    }
                    else
                    {
                        log_message(common::log::level_enum::info, WLogText_A("failed to read {}.{}.{}.{}.{}", 
                                                                                read_handle, no_err, why, this_read, total_read));
                        flag_obj = enumClass::kError;
                        break;
                    }
                }

                total_read += this_read;
                if(total_read >= stream_obj.max_size())
                {
                    log_message(common::log::level_enum::info, WLogText_A("failed to read, too long {}", total_read));
                    flag_obj = enumClass::kError;
                    break;
                }
                const auto& valid_span = buff_span.subspan(0, this_read);
                stream_obj.append_range(valid_span);
            }

        } while(0);

        mResources->set_redirect_result(flag_obj, std::move(stream_obj));
    }


    bool execute::impl::resume_process(std::size_t resumeCount)
    {
        DWORD lastResumeResult = 0;
        auto handle_copy = mResources->get_thread_handle();
        do
        {
            lastResumeResult = ::ResumeThread(handle_copy);
            if((DWORD)-1 == lastResumeResult)
            {
                log_message(common::log::level_enum::info, WLogText("failed to resume {}.{}", handle_copy, ::GetLastError()));
                break;
            }
        } while(lastResumeResult > 1 && (resumeCount > 0 ? --resumeCount > 0 : false));

        assert(!(lastResumeResult > 1));
        return !(lastResumeResult > 1);
    }

    std::uint64_t execute::impl::get_process_id() const
    {
        return mResources ? mResources->get_process_info().dwProcessId : 0;
    }


     //::DWORD process::impl::get_process_id() const 
     //{
     //   return mProcessId;
     //}

}

namespace os::software::process
{
    execute::execute() :
        mImpl(std::make_unique<impl>())
    {
    }

    execute::execute(const str::xtype app_name, const str::xtype cmd_line)
    {
    }

    execute::~execute()
    {
    }

    bool execute::create(bool suspended, bool redirect)
    {
        return mImpl->create(suspended, redirect);
    }

    bool execute::create(str::xtype app_name, str::xtype cmd_line, bool suspended, bool redirect)
    {
        return mImpl->create(app_name, cmd_line, suspended, redirect);
    }

    void execute::reset()
    {
        mImpl->reset();
    }

    execute_result_t execute::wait_for_exit(const wait_opt& opt)
    {
        return mImpl->wait_for_exit(opt);
    }

    std::uint64_t execute::get_process_id() const
    {
        return mImpl->get_process_id();
    }
}

#ifdef _tmemcpy
#undef _tmemcpy
#endif

#endif // _COMMON_OS_SOFTWARE_PROCESS_WIN_IMPL_H_