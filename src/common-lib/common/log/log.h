#pragma once
#ifndef _COMMON_LOG_H_
#define _COMMON_LOG_H_

#include <string>
#include <memory>

namespace common
{
    namespace log
    {
        class logger;
        using logger_ptr = std::shared_ptr<log::logger>;

        class manager
        {
        public:
            static manager& instance()
            {
                static manager obj;
                return obj;
            }
            ~manager();

            manager(const manager&) = delete;
            manager& operator=(const manager&) = delete;
            manager(manager&&) = delete;
            manager& operator=(manager&&) = delete;

            void set_use_default_filename()const;
            void set_log_dir(bool use_app_dir, const std::string& path)const;

            // 创建日志文件
            // append ： 是否追加而不是新建日文件？
            logger_ptr create_log_file(const std::string& logger_name, const char* path = nullptr);

            // 写入日志
            void write_log(const std::string& logger_name, int level, const std::string& text);
            void write_log(const std::string& logger_name, int level, const std::wstring& text);
            class impl;
        private:
            manager();

        private:
            std::unique_ptr<impl> mImpl;
        };


        // 总是 utf8
        class logger
        {
        public:
            ~logger();

            void set_level(int new_level);

            std::string get_file_path();
            int get_level(); // 易变

            // 写入日志
            void write_log(int level, const std::string& text);
            void write_log(int level, const std::wstring& text);
            //friend class manager;
        private:
            logger(const logger&) = delete;
            logger& operator=(const logger&) = delete;
            logger(logger&&) = delete;
            logger& operator=(logger&&) = delete;
            logger(std::string name, const std::string& path);

        private:
            friend class manager::impl;
            class impl;
            std::unique_ptr<impl> mImpl;
        };


        enum level_enum : int
        {
            trace = 0,
            debug,
            info,
            warn,
            err,
            err_debug_wnd = 4, // 仅在debug时候弹窗提示
            err_wnd = 4, // 总是弹窗
            exception, 
            critical = 5, // 崩溃
            off, // 可以通过 off 拒绝写入日志
            n_levels // 日志级别的数量7
        };
    }
};


#include "common/fmt/fmt-pch.h"
#ifdef _UNICODE
#define WLogAC      WLogAC_W
#define WLogText    WLogText_W
#else
#define WLogAC      WLogAC_A
#define WLogText    WLogText_A
#endif // _UNICODE

#define WLogText_W(str_, ...) xfmt::format(TEXT("{} ") TEXT(str_), __LINE__, __VA_ARGS__)
#define WLogText_A(str_, ...) xfmt::format("{} " str_, __LINE__, __VA_ARGS__)

#define WLogAC_W(log_name, level, str_, ...) common::log::manager::instance().write_log(log_name, level, WLogText_W(str_, __VA_ARGS__))
#define WLogAC_A(log_name, level, str_, ...) common::log::manager::instance().write_log(log_name, level, WLogText_A(str_, __VA_ARGS__))

#define WLogAC_OBJ(log_name, level, strObj) common::log::manager::instance().write_log(log_name, level, strObj)

#define WLogAC_GLOG(level, str_, ...) WLogAC("g_Log", level, str_, __VA_ARGS__)

#define WLogAC_EXCEPTION(str_, ...) WLogAC("exception", common::log::level_enum::trace, str_, __VA_ARGS__)
#define WLogAC_EXCEPTION_A(str_, ...) WLogAC_A("exception", common::log::level_enum::trace, str_, __VA_ARGS__)
#define WLogAC_EXCEPTION_W(str_, ...) WLogAC_W("exception", common::log::level_enum::trace, str_, __VA_ARGS__)

//#include <windows.h>
//#ifdef _DEBUG
//#define WLog_MSGBOX(log_name, str_, ...)  \
//std::wstring logStr = xfmt::format(TEXT("{}") TEXT(str_) __LINE__, __VA_ARGS__);\
//::MessageBox(::GetDesktopWindow(), logStr.c_str(), TEXT("提示"), MB_ICONERROR | MB_OK | MB_SETFOREGROUND | MB_SYSTEMMODAL);
//
//#else
//
//#define WLog_MSGBOX(log_name, str, ...)  \
//std::wstring logStr = xfmt::format(TEXT("{}") TEXT(str) __LINE__, __VA_ARGS__);\
//common::log::manager::instance().write_log(log_name, common::log::level_enum::info, strObj)
//#endif // _DEBUG模式下直接用弹窗


#endif // !_COMMON_LOG_H_