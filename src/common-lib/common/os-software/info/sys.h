#pragma once
#ifndef _COMMON_OS_SOFTWARE_INFO_SYS_H_
#define _COMMON_OS_SOFTWARE_INFO_SYS_H_

#include <string>
#include "common/marco_define.h"
#include "common/log/logger_help.h"

namespace os::software::info
{
    enum class platform_t
    {
        kUnknown,
        kWindows,
    };

    struct sys_os_info_t
    {
        platform_t     platform{ platform_t::kUnknown };
        std::uint32_t  major{0};
        std::uint32_t  minor{0};
        std::string    compunter_name;
        std::string    group_name;
    };


    class sys
    {
    public:
        sys() = default;
        DELETE_CLASS_FUNCTION(sys);
        static bool get_os_version(sys_os_info_t& out_value);
        static sys_os_info_t get_os_version();
        static sys_os_info_t get_os_temp_dir();
    };
}

#endif