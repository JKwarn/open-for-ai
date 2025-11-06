#pragma once
#ifndef _COMMON_OS_SOFTWARE_INFO_SYS_WIN_IMPL_H_
#define _COMMON_OS_SOFTWARE_INFO_SYS_WIN_IMPL_H_

#pragma comment(lib, "Netapi32.lib")

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <windows.h>
#include <lm.h>

#include <string>
#include "common/encode/string/string-encode.h"
#include "common/fmt/fmt-pch.h"
#include "common/log/log.h"
#include "../sys.h"


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


namespace os::software::info
{
    //OUT sOSVersion& Info
    bool sys::get_os_version(sys_os_info_t& out_value)
    {
        ::DWORD dwVersion = 0;
        ::WKSTA_INFO_100* pwkstaInfo = nullptr;
        NET_API_STATUS netStatus = ::NetWkstaGetInfo(NULL, 100, (BYTE**)&pwkstaInfo);
        if(netStatus != NERR_Success)
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} failed to get", netStatus));
            return false;
        }

        /*
PLATFORM_ID_DOS 300 MS-DOS平台。
PLATFORM_ID_OS2 400 OS/2平台。
PLATFORM_ID_NT  500 Windows NT平台。
PLATFORM_ID_OSF 600 OSF平台。
PLATFORM_ID_VMS 700 VMS平台。
        */
        out_value.platform = platform_t(pwkstaInfo->wki100_platform_id);
        out_value.major = pwkstaInfo->wki100_ver_major;
        out_value.minor = pwkstaInfo->wki100_ver_minor;
        out_value.compunter_name = encode::string::utf16_to_utf8(pwkstaInfo->wki100_computername);
        out_value.group_name = encode::string::utf16_to_utf8(pwkstaInfo->wki100_langroup);

        if(pwkstaInfo)
        {
            ::NetApiBufferFree(pwkstaInfo);
        }
        

        return true;
    }
    sys_os_info_t sys::get_os_version()
    {
        sys_os_info_t tempObj;
        get_os_version(tempObj);
        return tempObj;
    }
}

#endif