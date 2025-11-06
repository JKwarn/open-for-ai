#pragma once
#ifndef _COMMON_OS_SOFTWARE_NETWORK_SOCK_H_
#define _COMMON_OS_SOFTWARE_NETWORK_SOCK_H_

#include "./sock-pch.h"
#include <functional>
#include <expected>

namespace os::software::network
{
    class sock
    {
    public:
        enum class type
        {
            kTCP=1,
            kUDP,
            kRAW,
            kRDM,
            kSEQPACKET
        };

        template <typename T>
        using result = std::expected<T, std::string>;
        using void_result = result<void>;
        using bool_result = result<bool>;
        using str_resutl = result<std::string>;
        using uint32_resutl = result<std::uint32_t>;

        sock() = delete;
        ~sock() = delete;
        using create_cb = std::function<void(sock_fd)>;
        static sock_fd create_sock_ipv4(type value, const std::string_view& local_ip, std::uint16_t port, create_cb cb);
        static sock_fd create_sock_ipv4(type value, create_cb cb);
        static str_resutl get_sock_ipv4_str(const sock_fd& sock);
        static uint32_resutl get_sock_ipv4_integer(const sock_fd& sock);
        static bool set_sock_recv_out_time(sock_fd sock, std::int32_t sec, std::int32_t msc);
        static bool set_sock_reuse_addr(sock_fd sock);
        static bool call_pton(int P1, const char* P2, void* P3);
        static bool call_ntop(int P1, const void* P2, char* P3, std::uint32_t P4);
    private:
        static bool set_sock_opt(sock_fd sock, std::int32_t optLevel, std::int32_t optName, const char* optvalue, int optlen);
    };


}

#endif