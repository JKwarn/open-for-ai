#pragma once
#ifndef _COMMON_OS_HARDWARE_NETWORK_ADAPTER_H_
#define _COMMON_OS_HARDWARE_NETWORK_ADAPTER_H_

#include <vector>
#include <list>
#include <string>
#include "./adapter-pch.h"
#include "common/string_define.h"

namespace os::hardware::network
{
	struct mac_ip
	{
		std::string macAddr;
		std::string macDesc;
		std::string ipv4;
		std::string ipv6;
	};
	using mac_ip_container = std::list<mac_ip>;

	class adapter
	{
	public:
		adapter() = delete;
		~adapter() = delete;
		using container = std::vector<os_adapter_info>;
		static container get_all_adapter();
		static mac_ip_container get_mac_ip();
		static void sort_mac_by_ipv4(const std::string& hint_ip, mac_ip_container& dest_container);
	};
}


#endif