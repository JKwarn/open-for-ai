#include <memory>
#include <map>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "log.h"
#include "./spdlog/spdlog.h"
#include "./spdlog/sinks/basic_file_sink.h"
#include "./spdlog/sinks/rotating_file_sink.h"
#include "./spdlog/fmt/xchar.h"
#include "common/encode/string/string-encode.h"
#include "common/os-software/info/app.h"

std::string get_current_system_time_detailed()
{
    auto now = std::chrono::system_clock::now();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count() % 1000000;
    auto millis = micros / 1000;
    auto now_c = std::chrono::system_clock::to_time_t(now);

    std::tm tm_now;
#ifdef _WIN32
    ::localtime_s(&tm_now, &now_c);
#else
    ::localtime_r(&now_c, &tm_now);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_now, "%Y-%m-%d %H-%M-%S")
        << '-' << std::setfill('0') << std::setw(4) << millis
        << '-' << std::setfill('0') << std::setw(4) << (micros % 1000);

    return oss.str();
}

using namespace common;

/*--------------------------------------------------------------------------------------------------------------------------------------*/

class log::logger::impl
{
public:
    explicit impl(std::string name, const std::string& path);
    ~impl() = default;

    void set_level(int new_level);

    std::string get_file_path()const;
    int get_level()const;

    void write_log(int level, const std::string& text);

public:
    static spdlog::level::level_enum to_spdlog_level(int new_level, spdlog::level::level_enum hero = spdlog::level::level_enum::info);

private:
    std::string mLogName;
    std::shared_ptr<spdlog::logger> mWtiter;
};

log::logger::impl::impl(std::string name, const std::string& path)
    :mLogName(std::move(name))
{
    mWtiter = spdlog::basic_logger_mt(mLogName, path);
    if(mWtiter)
    {
        mWtiter->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%P] [%t] [%^%l%$] %v");
        mWtiter->set_level(spdlog::level::trace);
    }
}

void log::logger::impl::set_level(int new_level)
{
    mWtiter->set_level(to_spdlog_level(new_level));
}

std::string log::logger::impl::get_file_path()const
{
    const auto& file_sink = std::dynamic_pointer_cast<spdlog::sinks::basic_file_sink_mt>(mWtiter);
    if(file_sink)
    {
        return file_sink->filename();
    }
    else
    {
        return "";
    }
}

int log::logger::impl::get_level()const
{
    return int(mWtiter->level());
}

void log::logger::impl::write_log(int level, const std::string& text)
{
    mWtiter->log(to_spdlog_level(level), text);
    mWtiter->flush();
}

spdlog::level::level_enum log::logger::impl::to_spdlog_level(int new_level, spdlog::level::level_enum hero)
{
    return new_level > log::level_enum::n_levels ? hero : spdlog::level::level_enum(new_level);
}

log::logger::logger(std::string name, const std::string& path)
    : mImpl(std::make_unique<impl>(std::move(name), path))
{
}

log::logger::~logger()
{
}

void log::logger::set_level(int new_level)
{
    mImpl->set_level(new_level);
}

std::string common::log::logger::get_file_path()
{
    return mImpl->get_file_path();
}

int common::log::logger::get_level()
{
    return mImpl->get_level();
}

void log::logger::write_log(int level, const std::string& text)
{
    level = level > level_enum::off ? level_enum::off : level;
    switch(level)
    {
    case level_enum::off:
        break;
    default:
        mImpl->write_log(level, text);
        break;
    }
}

void log::logger::write_log(int level, const std::wstring& text)
{
    const std::string& utf8_text = encode::string::utf16_to_utf8(text);
    write_log(level, utf8_text);
}

/*--------------------------------------------------------------------------------------------------------------------------------------*/

class log::manager::impl
{
public:
    explicit impl();
    ~impl()=default;

    void set_use_default_filename();
    void set_log_dir(bool use_app_dir, const std::string& path);

    log::logger_ptr create_log_file(const std::string& logger_name, const char* filename);

    void write_log(const std::string& logger_name, int level, const std::string& text);

public:
    using logger_type = common::log::logger;
    using logger_container = std::map<std::string, std::shared_ptr<logger_type>>;

public:
    static void create_exception_log();
    static void write_exception(const std::string& msg);

public:
    static std::shared_ptr<spdlog::logger> mExceptionLog;

private:
    logger_container mLoggers;
    bool mUseDefaultFlag{ false };
    std::string mLogDir;
};

std::shared_ptr<spdlog::logger> common::log::manager::impl::mExceptionLog{nullptr};

log::manager::impl::impl()
{
    std::uint8_t step = 0;
    try
    {
        create_exception_log();
        ++step;
        mExceptionLog->info(get_current_system_time_detailed());
        mExceptionLog->flush();
        ++step;
    }
    catch(const spdlog::spdlog_ex& ex)
    {
        const auto& msg = xfmt::format("failed to create exception: pos={} ex={}", step, ex.what());
        throw std::runtime_error(msg); 
    }
    catch(const std::exception& e)
    {
        const auto& msg = xfmt::format("failed to create exception: pos={} e={}", step, e.what());
        throw std::runtime_error(msg);
    }
    catch(...)
    {
        const auto& msg = xfmt::format("failed to create exception: pos={} ...", step);
        throw std::runtime_error(msg);
    }
}

void log::manager::impl::set_use_default_filename()
{
    mUseDefaultFlag = true;
}

void log::manager::impl::set_log_dir(bool use_app_dir, const std::string& path)
{
    using namespace os::software;
    do
    {
        if(use_app_dir)
        {
            const std::string& dir_path = info::app<info::get::kDirPath>();
            if(dir_path.empty())
            {
                break;
            }
            mLogDir = xfmt::format("{}{}", dir_path, path);
            break;
        }

        if(path.empty())
        {
            mLogDir = "";
            break;
        }

        mLogDir = path;

    } while(0);

    auto last = mLogDir.back();
    if(!mLogDir.empty() && !(last == '\\' || last == '/'))
    {
        mLogDir.append("/");
    }
}

log::logger_ptr log::manager::impl::create_log_file(const std::string& logger_name, const char* newPath)
{
    using namespace os::software;
    const auto& iter = mLoggers.find(logger_name);
    if(mLoggers.cend() != iter && iter->second)
    {
        return iter->second;
    }

    static std::mutex m;
    log::logger_ptr logger;
    logger_type* lg = nullptr;
    try
    {
        std::string finalPath;
        if(nullptr == newPath)
        {
            if(mLogDir.empty())
            {
                const std::string& dir_path = info::app<info::get::kDirPath>();
                finalPath = xfmt::format("{}log/{}-{}.log",
                                         dir_path,
                                         logger_name, get_current_system_time_detailed());
            }
            else
                finalPath = xfmt::format("{}{}-{}.log", mLogDir, logger_name, get_current_system_time_detailed());
        }
        else
        {
            finalPath = newPath;
        };

        lg = new logger_type(logger_name, finalPath);
        logger.reset(lg);
        lg = nullptr;
        logger->write_log(log::level_enum::trace, get_current_system_time_detailed());

        std::lock_guard<std::mutex> lock(m);
        mLoggers[logger_name] = logger;
    }
    catch(const spdlog::spdlog_ex& ex)
    {
        if(lg)
        {
            delete lg;
        }

        std::string file = newPath ? newPath : "is null";
        const auto& msg = xfmt::format("{}.{} failed to create: {}", logger_name, file, ex.what());
        write_exception(msg);
        return nullptr;
    }

    return logger;
}

void log::manager::impl::write_log(const std::string& logger_name, int level, const std::string& text)
{
    try
    {
        auto it = mLoggers.find(logger_name);
        if(it != mLoggers.end())
        {
            it->second->write_log(level, text);
        }
        else
        {
            spdlog::error("Logger {} not found", logger_name);
        }
    }
    catch(const spdlog::spdlog_ex& ex)
    {
        const auto& msg = xfmt::format("{} failed to write: {}", logger_name, ex.what());
        write_exception(msg);
    }
    catch(const std::exception& ex)
    {
        const auto& msg = xfmt::format("{} failed to write: {}", logger_name, ex.what());
        write_exception(msg);
    }
}

void log::manager::impl::create_exception_log()
{
    using namespace os::software;
    static constexpr const char* kExceptionLogName{ "exception" };
    const std::string& dir_path = info::app<info::get::kDirPath>();
    std::string path = xfmt::format("{}spd_exception.log", dir_path);
    mExceptionLog = spdlog::rotating_logger_mt(kExceptionLogName, path, 5 * 1024 * 1024, 3);
    mExceptionLog->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%P] [%t] [%^%l%$] %v");
}

void log::manager::impl::write_exception(const std::string& msg)
{
    if(mExceptionLog)
    {
        mExceptionLog->info(msg);
        mExceptionLog->flush();
    }
}


log::manager::manager()
    : mImpl(std::make_unique<impl>())
{

}

log::manager::~manager()
{}

void log::manager::set_use_default_filename() const
{
    mImpl->set_use_default_filename();
}

void log::manager::set_log_dir(bool use_app_dir, const std::string& path) const
{
    mImpl->set_log_dir(use_app_dir, path);
}


log::logger_ptr log::manager::create_log_file(const std::string& logger_name, const char* path)
{
    return mImpl->create_log_file(logger_name, path);
}

void log::manager::write_log(const std::string& logger_name, int level, const std::string& text)
{
    level = level > level_enum::off ? level_enum::off : level;
    switch(level)
    {
    case level_enum::exception:
        mImpl->write_exception(text);
        break;
    case level_enum::off:
        break;
    default:
        mImpl->write_log(logger_name, level, text);
        break;
    }
}

void log::manager::write_log(const std::string& logger_name, int level, const std::wstring& text)
{
    const std::string& utf8_text = encode::string::utf16_to_utf8(text);
    write_log(logger_name, level, utf8_text);
}
