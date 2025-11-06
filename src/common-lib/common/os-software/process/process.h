#pragma once
#include <vector>
#include <functional>
#include <cstdint>
#include <memory>

#include "common/string_define.h"

//
//extern void ErrorText(PCTSTR lpszFunction);
//
//namespace os::software::process
//{
//    struct redirect_handles
//    {
//        HANDLE childProcErrPipeW{ NULL };
//        HANDLE childProcErrPipeR{ NULL };
//        HANDLE childProcOutputPipeW{ NULL };
//        HANDLE childProcOutputPipeR{ NULL };
//        HANDLE childProcInputPipeW{ NULL };
//        HANDLE childProcInputPipeR{ NULL };
//    };
//
//    struct redirect_result_t
//    {
//        enum flag_t
//        {
//            kError = 0,
//            kSucced,
//            kVoid,
//        };
//        using stream_t = std::vector<std::uint8_t>;
//        using essence_t = std::vector<HANDLE>;
//
//        flag_t mRedirectFlag{ flag_t::kVoid };
//        stream_t mRedirectSteam;
//    };
//
//    struct process_info_t
//    {
//        using exit_code_t = std::make_signed<std::size_t>::type;
//        enum class status_type_t :std::uint8_t
//        {
//            kException = 0,
//            kFailed,
//            kStilActive,
//            kFinish,
//            kNotCreate,
//            kUnknown,
//        };
//
//        status_type_t mProcessStatus{ status_type_t::kUnknown };
//        exit_code_t mExitCode{ 0 };
//        PROCESS_INFORMATION mHandleID{ 0 };
//    };
//
//    struct execute_result_t
//    {
//        process_info_t mProcessInfo;
//        redirect_result_t mRedirectResult;
//        str::xtype mRunLogText;
//    };
//
//    struct wait_opt
//    {
//        bool CreatePipeRedirect(str::xtype& logText);
//
//        enum class execute_mode_t
//        {
//            kSyncExited = 0,
//            kAsyncExited,
//            kPromiseExited,
//        };
//
//        str::xtype app_name;
//        str::xtype cmd_line;
//        execute_mode_t execute_mode{ execute_mode_t::kSyncExited };
//        std::uint32_t max_wait_count = INFINITE;
//        DWORD wait_time_per = INFINITE;
//        bool need_redirect = false;
//        redirect_handles mPipeHandles;
//    };
//
//    using async_callback_t = std::function<void(execute_result_t)>;
//    execute_result_t Execute(wait_opt& opt, const async_callback_t& callbcakFunction);
//
//
//}
namespace os::software::process
{
    struct redirect_result_t
    {
        enum flag_t
        {
            kError = 0,
            kSucced,
            kUnknown,
        };
        using stream_t = std::vector<std::uint8_t>;

        flag_t flag{ flag_t::kUnknown };
        stream_t stream;
    };


    struct execute_result_t
    {
        using exit_code_t = std::make_signed<std::size_t>::type;
        enum class status_type_t :std::uint8_t
        {
            kException = 0,
            kFailed,
            kStilActive,
            kFinish,
            kNotCreate,
            kUnknown,
        };

        status_type_t status{ status_type_t::kUnknown };
        exit_code_t exit_code{ 0 };
        redirect_result_t redirect;
        //str::xtype mRunLogText;
    };

    struct wait_opt
    {
        using count_t = std::uint32_t;
        using async_callback_t = std::function<void(execute_result_t)>;

        //enum class execute_mode_t
        //{
        //    kSyncExited = 0,
        //    kAsyncExited,
        //    kPromiseExited,
        //};

        //execute_mode_t execute_mode{ execute_mode_t::kSyncExited };
        count_t max_wait_count = 0xFFFFFFFF;
        count_t wait_time_per = 0xFFFFFFFF;
        bool need_redirect = false;
        async_callback_t callback;
    };

    //execute_result_t Execute(wait_opt& opt, const async_callback_t& callbcakFunction);

};

namespace os::software::process
{
    class execute
    {
    public:
        execute();
        execute(const str::xtype app_name, const str::xtype cmd_line);
        ~execute();

        execute(const execute&) = delete;
        execute& operator=(const execute&) = delete;

        bool create(bool suspended, bool redirect);
        bool create(str::xtype app_name, str::xtype cmd_line, bool suspended = true, bool redirect = false);

        void reset();

        execute_result_t wait_for_exit(const wait_opt& opt);

        std::uint64_t get_process_id() const;

    private:
        class impl;
        std::unique_ptr<impl> mImpl;
    };

}
