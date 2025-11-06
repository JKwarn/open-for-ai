#pragma once
#ifndef _COMMON_OS_HARDWARE_NETWORK_ADAPTER_PCH_H_
#define _COMMON_OS_HARDWARE_NETWORK_ADAPTER_PCH_H_

namespace os::hardware::network
{
    enum class adapter_category
    {
        kWired,
        kWireless,
        kVirtual,
        kUnknown
    };
}

#ifdef _WIN32
#include <iphlpapi.h>
namespace os::hardware::network
{
    using os_adapter_info = IP_ADAPTER_INFO;
}
#endif // _WIN32


#endif