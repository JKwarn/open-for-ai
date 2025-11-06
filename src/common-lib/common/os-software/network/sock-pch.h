#pragma once
#ifndef _COMMON_OS_SOFTWARE_NETWORK_SOCK_PCH_H_
#define _COMMON_OS_SOFTWARE_NETWORK_SOCK_PCH_H_

#include <string>
#include <deque>

//constexpr wchar_t gServiceName[]{ L"xixiexam主机服务" };
//
//struct host_config
//{
//    std::uint16_t   mPort{ 0 };
//    const char* mRemoterGroupAddr{ "224.0.0.1" };
//    std::string     mLocalAddr;
//};
//
//enum class host_event
//{
//    kUnknown,
//    Open,
//    Close
//};
//
//using DWORD = unsigned long;
//using LPWSTR = wchar_t*;
namespace os::software::network
{

#ifdef _WIN32
#include <winsock2.h>
    using sock_fd = SOCKET;

    struct sender_ipv4_info_t
    {
        sockaddr_in addr{ 0 };
        char str[20]{ 0 };
        std::uint16_t port{ 0 };
    };


    //struct sock_opt
    //{
    //    bool invalid = true;
    //    int optLevel = 0;
    //    int optName = 0;
    //    std::string optval;
    //    const char* w = optval.data();
    //    template<typename T>
    //    sock_opt& operator= (T other)
    //    {
    //        if(std::is_same_v<T, sock_opt> && this == (void*)&other)
    //        {
    //            return *this;
    //        }

    //        this->invalid = false;
    //        auto len = sizeof(T);
    //        this->optval.resize(len);
    //        ::memcpy((void*)this->optval.data(), &other, len);
    //        return *this;
    //    }
    //};


#endif // _WIN32


}

#endif