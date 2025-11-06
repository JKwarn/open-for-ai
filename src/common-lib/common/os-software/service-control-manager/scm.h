#pragma once
#ifndef _COMMON_OS_SOFTWARE_SCM_H_
#define _COMMON_OS_SOFTWARE_SCM_H_

#include <memory>
#include "common/string_define.h"

namespace os::software::service
{
    class scm
    {
    public:
        enum class status
        {
            kNotExist = -1,
            kUnknown,
            kStopped,
            kStarting,
            kStopping,
            kRunning,
            kContinuing,
            kPausing,
            kPaused
        };

        //{
        //    //SC_HANDLE hSCManager;
        //    //LPCSTR    lpServiceName;
        //    //LPCSTR    lpDisplayName;
        //    DWORD     dwDesiredAccess = SERVICE_ALL_ACCESS;
        //    DWORD     dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        //    DWORD     dwStartType;
        //    DWORD     dwErrorControl;
        //    LPCSTR    lpBinaryPathName;
        //    LPCSTR    lpLoadOrderGroup;
        //    LPDWORD   lpdwTagId;
        //    LPCSTR    lpDependencies;
        //    LPCSTR    lpServiceStartName;
        //    LPCSTR    lpPasswor;
        //};

        scm(const str::xtype& computerName); // scm 句柄 
        ~scm();
        scm(const scm&) = delete;
        scm& operator=(const scm&) = delete;
        scm(scm&&) = delete;
        scm& operator=(scm&&) = delete;

        bool install(const str::xtype& binaryPath, const str::xtype& displayName, bool auto_start);
        bool uninstall(const str::xtype& serviceName);
        bool start(const str::xtype& serviceName);
        bool stop(const str::xtype& serviceName);
        bool pause(const str::xtype& serviceName);
        bool cancel_pause(const str::xtype& serviceName);

        bool is_this_status(const str::xtype& serviceName, status& that);
        bool is_exist(const str::xtype& serviceName);

        status get_status(const str::xtype& serviceName) const;
        str::xtype get_display_name(const str::xtype& serviceName) const;

        bool set_description(const str::xtype& serviceName, const str::xtype& description);
        bool set_start_type(const str::xtype& serviceName, unsigned long startType);

    private:
        class impl;
        std::unique_ptr<impl> mImpl;
    };
}
#endif