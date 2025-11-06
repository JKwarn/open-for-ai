#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#include <algorithm>
#include <type_traits>
#include "adapter.h"
#include "common/log/log.h"

template<typename T>
    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
void log_message(int level, const T& message)
{
    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("os-nic") };
    if(log)
    {
        log->write_log(level, message);
    }
}

using namespace os::hardware::network;
adapter::container os::hardware::network::adapter::get_all_adapter()
{
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)::malloc(sizeof(IP_ADAPTER_INFO));
    adapter::container adapterInfoContainer;
    do
    {
        if(pAdapterInfo == NULL)
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} failed to allocation", ::GetLastError()));
            break;
        }
        
        ULONG buff_len = sizeof(IP_ADAPTER_INFO);
        if(::GetAdaptersInfo(pAdapterInfo, &buff_len) == ERROR_BUFFER_OVERFLOW)
        {
            ::free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)::malloc(buff_len);
            if(pAdapterInfo == NULL)
            {
                log_message(common::log::level_enum::err, WLogText_A(".{} failed to allocation second time", ::GetLastError()));
                break;
            }
        }

        if(NO_ERROR == ::GetAdaptersInfo(pAdapterInfo, &buff_len))
        {
            ::PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            std::size_t oldCount = 0;
            do
            {
                oldCount = adapterInfoContainer.size();
                adapterInfoContainer.emplace(adapterInfoContainer.end(), *pAdapter);

                if(oldCount == adapterInfoContainer.size())
                {
                    std::string mac = xfmt::format("{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}", 
                                                   pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                                                   pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]
                    );

                    log_message(common::log::level_enum::err, WLogText_A(".{} failed to add ", mac));
                }
                pAdapter = pAdapter->Next;

            } while(pAdapter);
        }
        else
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} failed to get adapters info", ::GetLastError()));
        }

    } while(0);

    if(pAdapterInfo)
    {
        ::free(pAdapterInfo);
    }

    return adapterInfoContainer;
}

os::hardware::network::mac_ip_container os::hardware::network::adapter::get_mac_ip()
{
    mac_ip_container tempObj;
    const auto& container = get_all_adapter();
    std::size_t oldCount = 0;
    std::string mac;
    for(const auto& ele : container)
    { 
        mac = xfmt::format("{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                           ele.Address[0], ele.Address[1], ele.Address[2],
                           ele.Address[3], ele.Address[4], ele.Address[5]
        );

        oldCount = tempObj.size();
        tempObj.emplace_back(mac, ele.Description, ele.IpAddressList.IpAddress.String, "");
        if(oldCount == tempObj.size())
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} failed to add ", mac));
        }
    }
    
    return tempObj;
}

void os::hardware::network::adapter::sort_mac_by_ipv4(const std::string& hint_ipv4,  mac_ip_container& dest_container)
{
    do
    {
        if(hint_ipv4.empty()
           || hint_ipv4.compare("0.0.0.0") == 0
           || hint_ipv4.compare("127.0.0.1") == 0)
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} invalid", hint_ipv4));
            break;
        }

        if(dest_container.empty())
        {
            log_message(common::log::level_enum::err, WLogText_A("container invalid"));
            break;
        }

        if(1 == dest_container.size())
        {
            break;
        }


        ::IN_ADDR hintAddr;
        ::INT isIpv4 = ::InetPtonA(AF_INET, hint_ipv4.c_str(), &hintAddr);
        if(1 != isIpv4)
        {
            log_message(common::log::level_enum::err, WLogText_A(".{} failed to convert {}.{}", hint_ipv4, isIpv4, ::WSAGetLastError()));
            break;
        }

        std::string rs;
        std::string ls;
        using element_type = mac_ip_container::value_type;
        auto func = [&](const element_type& r, const element_type& l)
            {

                rs = r.ipv4;
                ls = l.ipv4;
                int pos1 = 0;
                std::size_t maxx = rs.length() >= hint_ipv4.length() ? hint_ipv4.length() : rs.length();
                for(std::size_t i = 0; i < maxx; i++)
                {
                    if(rs[i] == hint_ipv4[i])
                    {
                        ++pos1;
                    }
                }

                int pos2 = 0;
                std::size_t maxx2 = ls.length() >= hint_ipv4.length() ? hint_ipv4.length() : ls.length();
                for(std::size_t i = 0; i < maxx2; i++)
                {
                    if(ls[i] == hint_ipv4[i])
                    {
                        ++pos2;
                    }
                }

                return pos1 > pos2;
            };

        try
        {
            std::stable_sort(dest_container.begin(), dest_container.end(), func);
        }
        catch(const std::exception& e)
        {
            log_message(common::log::level_enum::exception, WLogText_A(".{} failed to sort{}.{}", e.what(), rs, ls));
        }

    } while(0);
}
