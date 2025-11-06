#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <WinSock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

#include <algorithm>
#include <type_traits>
#include <system_error>
#include <atomic>

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif // !__STDC_WANT_LIB_EXT1__
#include <string.h>

#include "sock.h"
#include "common/log/log.h"
#include "common/os-software/info/sys.h"

template<typename T>
    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
static void log_message(int level, const T& message)
{
    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("net-api") };
    if(log)
    {
        log->write_log(level, message);
    }
}

namespace os::software::network
{
    class win_sock_initialize
    {
    public:
        win_sock_initialize();
        ~win_sock_initialize();

        win_sock_initialize(const win_sock_initialize&) = delete;
        win_sock_initialize(win_sock_initialize&&) = delete;
        win_sock_initialize& operator=(const win_sock_initialize&) = delete;
        win_sock_initialize& operator=(win_sock_initialize&&) = delete;
    private:
        std::atomic<bool> mInit;
    };

    win_sock_initialize::win_sock_initialize()
        : mInit{ false }
    {
        ::WSADATA WSAData;
        if(::WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
        {
            log_message(common::log::level_enum::critical, WLogText_A(".{} failed to startup", ::WSAGetLastError()));
            throw std::exception("network critical");
        }
        else
        {
            mInit.store(true);
        }
    }

    win_sock_initialize::~win_sock_initialize()
    {
        if(mInit)
        {
            ::WSACleanup();
        }
    }
    static const win_sock_initialize kWinSockInit;
};

namespace os::software::network
{
    static const os::software::info::sys_os_info_t kOsInfo{ os::software::info::sys::get_os_version() };

    std::expected<::sockaddr_in, std::string> get_local_sock_info(const sock_fd& sock)
    {
        ::sockaddr obj;
        int len = sizeof(obj);
        auto result = ::getsockname(sock, &obj, &len);
        if(result == SOCKET_ERROR)
        {
            return std::unexpected(xfmt::format("{}.{}.{} failed to get", __LINE__, sock, ::WSAGetLastError()));
        }

        ::sockaddr_in* ret = (::sockaddr_in*)&obj;
        return sockaddr_in(*ret);
    };




    sock_fd os::software::network::sock::create_sock_ipv4(type value, const std::string_view& local_ip, std::uint16_t port, create_cb cb)
    {
        sock_fd result = ::socket(AF_INET, static_cast<int>(value), 0);
        if(INVALID_SOCKET == result)
        {
            log_message(common::log::level_enum::err_debug_wnd, WLogText_A("{}.{}.{}.{} failed to create sock",
                                                                     static_cast<int>(value),
                                                                     local_ip, port,
                                                                     ::WSAGetLastError()));
        }
        else
        {
            if(cb)
            {
                cb(result);
            }
        }
        return result;
    }

    sock_fd sock::create_sock_ipv4(type value, create_cb cb)
    {
        sock_fd result = ::socket(AF_INET, static_cast<int>(value), 0);
        if(INVALID_SOCKET != result && cb)
        {
            cb(result);
        }
        return result;
    }

    sock::str_resutl sock::get_sock_ipv4_str(const sock_fd& sock)
    {
        auto ret = get_sock_ipv4_integer(sock);
        if(ret)
        {
            auto uint = *ret;
            char str[20]{ 0 };
            auto ntop_result = ::InetNtopA(AF_INET, &uint, str, 20);
            if(NULL == ntop_result)
            {
                auto msg = WLogText_A("{}.{}.{} failed to convert ip", str, static_cast<void*>(&ntop_result), ::WSAGetLastError());
                return std::unexpected(std::move(msg));
            }
            else
            {
                return str;
            }
        }
        else
        {
            return std::unexpected(ret.error());
        }
    }

    sock::uint32_resutl sock::get_sock_ipv4_integer(const sock_fd& sock)
    {
        auto ret = get_local_sock_info(sock);
        if(ret)
        {
            return ret.value().sin_addr.S_un.S_addr;
        }
        else
        {
            return std::unexpected(ret.error());
        }
    }

    bool sock::set_sock_recv_out_time(sock_fd sock, std::int32_t sec, std::int32_t msc)
    {
        ::timeval t;
        t.tv_sec = sec;
        t.tv_usec = msc;
        return set_sock_opt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
    }

    bool sock::set_sock_reuse_addr(sock_fd sock)
    {
        ::DWORD value = TRUE;
        return set_sock_opt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&value, sizeof(value));
    }

    bool sock::call_pton(int P1, const char* P2, void* P3)
    {
        int call_result = -1;
        if(nullptr == P3)
        {
            std::uint32_t temp;
            call_result = ::InetPtonA(P1, P2, &temp);
        }
        else
        {
            call_result = ::InetPtonA(P1, P2, P3);
        }

        if(1 == call_result)
        {
            return true;
        }

        size_t len = 0;
        size_t overload = 0;
        if(P2)
        {
            if(AF_INET == P1)
            {
                overload = 3 * 4 + 3 + 2;
                len = ::strnlen_s(P2, overload);
            }
            else if(AF_INET6 == P1)
            {
                overload = 4 * 8 + 7 + 2;
                len = ::strnlen_s(P2, overload);
            }
            else
            {
                len = -1;
            }
        }

        std::string tempLog;

        if(0 == len)
        {
            tempLog = WLogText_A("failed to call P=null {}", overload);
        }
        else if(-1 == len)
        {
            tempLog = WLogText_A("failed to call P!=4.6 {}", overload);
        }
        else if(overload == len)
        {
            std::string temp{ P2, overload };
            tempLog = WLogText_A("failed to call overload.{}", temp);
        }

        if(FALSE == tempLog.empty())
        {
            log_message(common::log::level_enum::err_debug_wnd, tempLog);
        }
        else
        {
            tempLog = WLogText_A("failed to call.re={}.err={}.P:{}.P:{}", call_result, ::WSAGetLastError(), P1, P2);
            log_message(common::log::level_enum::err_debug_wnd, tempLog);
        }

        return false;
    }

    bool sock::call_ntop(int P1, const void* P2, char* P3, std::uint32_t P4)
    {
        auto call_result = ::InetNtopA(P1, P2, P3, P4);
        if(NULL == call_result)
        {
            const auto& tempLog = WLogText_A("failed to call.re={}.err={}.P{}.{}.{}.{}", 
                                             call_result, ::WSAGetLastError(), 
                                             P1, static_cast<const void*>(P2), static_cast<void*>(P3), P4);
            log_message(common::log::level_enum::err_debug_wnd, tempLog);
        }
        return NULL != call_result;
    }

    bool sock::set_sock_opt(sock_fd sock, std::int32_t optLevel, std::int32_t optName, const char* optvalue, int optlen)
    {
        log_message(common::log::level_enum::trace, WLogText_A("set {}.{}.{}.{}", sock, optLevel, optName, static_cast<const void*>(optvalue)));

        if(SOCKET_ERROR == ::setsockopt(sock, optLevel, optName, optvalue, optlen))
        {
            if(kOsInfo.major)
            {
                if(optName == 0x3008 && kOsInfo.major < 10)
                    return true;
            }

            auto ret = get_sock_ipv4_str(sock);
            log_message(common::log::level_enum::err_debug_wnd, WLogText_A("{}.{}.{} failed to set opt {}.{}",
                                                                           ret.value_or("err"),sock,::WSAGetLastError(),
                                                                           optLevel, optName));
            return false;
        }

        return true;
    }
};