#pragma once
#include <string>

constexpr wchar_t gKServiceName[]{ L"xixiexam_student" };
constexpr char gKRemoteGroupIpv4[]{ "224.0.0.1" };
constexpr int gKDefaultPort = 9811;

struct host_config
{
    std::uint16_t   mPort{ 0 };
    const char*     mRemoterGroupAddr{ gKRemoteGroupIpv4 };
    std::string     mLocalAddr;
};

enum class host_event
{
    kUnknown,
    kOpen,
    kClose
};

using DWORD = unsigned long;
using LPWSTR = wchar_t*;

class xixi_host_service
{
public:
    static void __stdcall service_main(::DWORD argc, LPWSTR* argv);
    static void __stdcall service_ctrl_handler(::DWORD ctrl_code);

    static bool do_start();
    static void do_stop();
    static void do_pause();
    static void do_continue();
private:
    static void report_service_status(std::uint32_t currentstate, std::uint32_t exitcode, std::uint32_t waithint);
    static bool read_host_config(host_config& out);
    static bool running;
};
