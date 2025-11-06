#pragma once
#ifndef _COMMON_OS_SOFTWARE_SERVICE_H_
#define _COMMON_OS_SOFTWARE_SERVICE_H_

#include <memory>
#include <string>
#include <functional>
#include <windows.h>

namespace os::services
{
    class windows_service 
    {
    public:
        enum class state 
        {
            stopped,
            start_pending,
            running,
            pause_pending,
            paused,
            continue_pending
        };

        explicit windows_service(std::wstring_view name);
        ~windows_service();

        windows_service(const windows_service&) = delete;
        windows_service& operator=(const windows_service&) = delete;

        void start();
        void stop();
        void pause();
        void resume();

        state current_state() const noexcept;
        std::wstring_view name() const noexcept;

        using control_handler = std::function<bool(DWORD control_code)>;

        void set_control_handler(control_handler handler);

        static void install(
            std::wstring_view service_name,
            std::wstring_view display_name,
            DWORD start_type = SERVICE_DEMAND_START
        );

        static void uninstall(std::wstring_view service_name);

    private:
        class impl;
        std::unique_ptr<impl> pimpl_;
    };
} // namespace os::services
#endif