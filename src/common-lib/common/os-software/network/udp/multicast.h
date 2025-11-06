#pragma once

#include <memory>
#include <vector>
#include "common/marco_define.h"

namespace os::software::network::udp
{
    class control_event_t
    {
    public:
        enum class type_t
        {
            kClose = 0,
            kPause,
            kContinue,
            kTask,
            kRecverWndIsCreated,
            kHeartbeatHostChanged,
            kHeartbeatJsonChanged,
        };

        enum class wait_result_t
        {
            kAbandon,
            kSignaled,
            kTimeOut,
            kFailed,
        };

        using HANDLE = void*;
        using DWORD = std::uint32_t;
        using type_container_t = std::vector<type_t>;
        using event_container_t = std::vector<HANDLE>;
        using callback_t = std::function<void(wait_result_t)>;

        control_event_t(type_container_t types);
        ~control_event_t();
        //control_event_t& operator=(const control_event_t& other);
        //DELETE_CLASS_FUNCTION(control_event_t);
        //control_event_t(const control_event_t&) = delete;
        //control_event_t(control_event_t&&) = delete;
        //control_event_t& operator=(control_event_t&&) = delete;

        HANDLE get_signle_event(type_t dest);
        HANDLE* get_events();
        void set_event(type_t dest);
        std::size_t get_count() const;
        bool is_close_event(std::size_t index)const;

        bool wait_specified_event(const type_t& type, std::uint32_t timeout = INFINITE);
        void wait_specified_event(const type_t& type, std::uint32_t timeout, callback_t func);
        bool wait_close_event(std::uint32_t timeout = INFINITE);
    private:
        class impl;
        std::shared_ptr<impl> mImpl;
    };

	class multicast
	{
	public:
		multicast();
		~multicast();
        DELETE_CLASS_FUNCTION(multicast);


		bool create(const std::string& native_ipv4, const std::string& remote_group_ipv4, int multicast_port, control_event_t& out_value);
        void run();
		void stop();
        void set_temp_path(const std::filesystem::path& obj);
	private:
		class impl;
		std::unique_ptr<impl> mImpl;
	};
}