#pragma once
#include "./log.h"
#include <type_traits>

namespace common::log
{
    class logger_help
    {
    public:
        // 用于日志记录
        template<typename T>
            requires (std::is_convertible_v<T, std::string> 
                      || std::is_convertible_v<T, std::wstring>
                      || std::is_convertible_v<T, std::string_view>
                      || std::is_convertible_v<T, std::wstring_view>
                     )
        void log_message(int level, const T& message)
        {
            if(mLoggers)
            {
                mLoggers->write_log(level, message);
            }
        }

    protected:
        logger_help(std::string_view name, const char* path = nullptr)
        {
            mLoggers = common::log::manager::instance().create_log_file(name.data(), path);
        };
        ~logger_help() = default;

        common::log::logger_ptr mLoggers;
    };
};

/*

log_message(common::log::level_enum::trace, "worker on line");

log_message(common::log::level_enum::info, WLogText_A("failed to create .{:s} closed", sender.str));


// 用于日志记录
template<typename T>
    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
static void log_message(int level, const T& message)
{
    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("info") };
    if(log)
    {
        log->write_log(level, message);
    }
}


bool no_err{false};
do
{

}while(0);
return no_err;

*/