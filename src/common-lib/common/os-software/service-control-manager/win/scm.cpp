#include <vector>
#include <system_error>
#include <map>
#include <cassert>
#include <shared_mutex>
#include "common/os-software/service-control-manager/scm.h"
#include "common/log/log.h"
#include "common/log/logger_help.h"
#include "common/encode/string/string-encode.h"
#include "common/fmt/fmt-pch.h"

namespace os::software::service
{
#define EXPAN(X) {X, TO_TEXT(#X)}
    using access_right_t = std::size_t;

    const std::map<access_right_t, str::xtype> kSCM_AR_description
    {
        EXPAN(SC_MANAGER_ENUMERATE_SERVICE),
        EXPAN(SC_MANAGER_QUERY_LOCK_STATUS),
        EXPAN(SC_MANAGER_CREATE_SERVICE),
        EXPAN(SC_MANAGER_MODIFY_BOOT_CONFIG),
        EXPAN(SC_MANAGER_CONNECT),
        EXPAN(SC_MANAGER_LOCK),
        EXPAN(SC_MANAGER_ALL_ACCESS),
        EXPAN(GENERIC_READ),
        EXPAN(GENERIC_WRITE),
        EXPAN(GENERIC_EXECUTE),
        EXPAN(GENERIC_ALL),
    };

    const std::map<access_right_t, access_right_t> kSCM_AR_generic_level
    {
        {STANDARD_RIGHTS_READ,GENERIC_READ},
        {SC_MANAGER_ENUMERATE_SERVICE,GENERIC_READ},
        {SC_MANAGER_QUERY_LOCK_STATUS,GENERIC_READ},

        {STANDARD_RIGHTS_WRITE,GENERIC_WRITE},
        {SC_MANAGER_CREATE_SERVICE,GENERIC_WRITE},
        {SC_MANAGER_MODIFY_BOOT_CONFIG,GENERIC_WRITE},

        {STANDARD_RIGHTS_EXECUTE,GENERIC_EXECUTE},
        {SC_MANAGER_CONNECT,GENERIC_EXECUTE},
        {SC_MANAGER_LOCK,GENERIC_EXECUTE},

        {SC_MANAGER_ALL_ACCESS,GENERIC_ALL},
    };

    const std::map<access_right_t, str::xtype> kSAR_description
    {
        EXPAN(SERVICE_USER_DEFINED_CONTROL),
        EXPAN(SERVICE_STOP),
        EXPAN(SERVICE_START),
        EXPAN(SERVICE_QUERY_STATUS),
        EXPAN(SERVICE_QUERY_CONFIG),
        EXPAN(SERVICE_PAUSE_CONTINUE),
        EXPAN(SERVICE_INTERROGATE),
        EXPAN(SERVICE_ENUMERATE_DEPENDENTS),
        EXPAN(SERVICE_CHANGE_CONFIG),
        EXPAN(SERVICE_ALL_ACCESS),
        EXPAN(ACCESS_SYSTEM_SECURITY),
        EXPAN(DELETE),
        EXPAN(READ_CONTROL),
        EXPAN(WRITE_DAC),
        EXPAN(WRITE_OWNER),
        EXPAN(GENERIC_READ),
        EXPAN(GENERIC_WRITE),
        EXPAN(GENERIC_EXECUTE),
    };

    const std::map<access_right_t, access_right_t> kSAR_generic_level
    {
        {STANDARD_RIGHTS_READ,GENERIC_READ},
        {SERVICE_QUERY_CONFIG,GENERIC_READ},
        {SERVICE_QUERY_STATUS,GENERIC_READ},
        {SERVICE_INTERROGATE,GENERIC_READ},
        {SERVICE_ENUMERATE_DEPENDENTS,GENERIC_READ},

        {STANDARD_RIGHTS_WRITE,GENERIC_WRITE},
        {SERVICE_CHANGE_CONFIG,GENERIC_WRITE},

        {STANDARD_RIGHTS_EXECUTE,GENERIC_EXECUTE},
        {SERVICE_START,GENERIC_EXECUTE},
        {SERVICE_STOP,GENERIC_EXECUTE},
        {SERVICE_PAUSE_CONTINUE,GENERIC_EXECUTE},
        {SERVICE_USER_DEFINED_CONTROL,GENERIC_EXECUTE},

        {SC_MANAGER_ALL_ACCESS,GENERIC_ALL},
    };


#define CEND -1
    const decltype(kSCM_AR_description)::value_type kCend = EXPAN(CEND);
    auto get_scm_access_right_desc(access_right_t access_right)
    {
        const auto& iter = kSCM_AR_description.find(access_right);
        return iter == kSCM_AR_description.cend() ? kCend.second : iter->second;
    }

    auto get_service_access_right_desc(access_right_t access_right)
    {
        const auto& iter = kSAR_description.find(access_right);
        return iter == kSAR_description.cend() ? kCend.second : iter->second;
    }

    bool get_scm_ar_by_service_ar(common::log::logger_help& logger, const access_right_t& service_ar, access_right_t& scm_ar)
    {
        bool find{ false };
        int find_count{ 0 };
        auto func = [&](const std::map<access_right_t, access_right_t> generic_map, 
                        const std::map<access_right_t, str::xtype> specific_map,
                        const access_right_t& in,
                        access_right_t& out)->bool
            {
                do
                {
                    const auto& generic_iter = generic_map.find(in);
                    if(generic_iter != generic_map.cend())
                    {
                        out = generic_iter->second;
                        break;
                    }

                    const auto& specific_iter = specific_map.find(in);
                    if(specific_iter == specific_map.cend())
                    {
                        logger.log_message(common::log::level_enum::info, WLogText_A("{} unknown ar {}", find_count, in));
                        return false;
                    }
                    else
                    {
                        out = GENERIC_ALL;
                    }

                } while(0);

                return true;
            };

        access_right_t SAR_out{ 0 };
        if(func(kSAR_generic_level, kSAR_description, service_ar, SAR_out))
        {
            find = func(kSCM_AR_generic_level, kSCM_AR_description, SAR_out, scm_ar);
        }

        return find;
    }



#undef CEND
#undef EXPAN

};

namespace os::software::service
{
    template<typename T>
    class resource
    {
    public:
        using type = T;
        explicit resource(T handle);
        ~resource();
        resource(const resource&) = default;
        resource& operator=(const resource&) = delete;
        T get_copy() const;
        void reset(T new_handle);
        operator bool() const;


    private:
        T mHandle;
    };
}

namespace os::software::service
{
    template<typename T>
    resource<T>::resource(T handle)
        : mHandle(handle)
    {}

    template<typename T>
    resource<T>::~resource()
    {
        if(mHandle)
        {
            ::CloseServiceHandle(mHandle);
        }
        mHandle = NULL;
    }

    template<typename T>
    T resource<T>::get_copy() const
    {
        return mHandle;
    }

    template<typename T>
    void resource<T>::reset(T new_handle)
    {
        if(mHandle)
        {
            ::CloseServiceHandle(mHandle);
        }
        mHandle = new_handle;
    }

    template<typename T>
    resource<T>::operator bool() const
    {
        return mHandle != nullptr;
    }
}

namespace os::software::service
{
    class scm::impl : public common::log::logger_help
    {
    public:
        explicit impl(const str::xtype& computerName);
        ~impl();
        bool install(const str::xtype& binaryPath, const str::xtype& displayName, bool auto_start);
        bool uninstall(const str::xtype& service_name);
        bool start(const str::xtype& service_name);
        bool stop(const str::xtype& service_name);
        bool pause(const str::xtype& service_name);
        bool cancel_pause(const str::xtype& service_name);
        bool do_control_service(const str::xtype& service_name, ::DWORD access, ::DWORD dwControl);

        str::xtype get_display_name(const str::xtype& service_name);
        scm::status get_status(const str::xtype& service_name);

        bool set_start_type(const str::xtype& service_name, ::DWORD startType);
        bool set_description(const str::xtype& service_name, const str::xtype& description);

        bool is_exist(const str::xtype& service_name);

    private:
        bool open_service_and_store(const str::xtype& service_name, ::DWORD service_ar);
        bool open_service(const str::xtype& service_name, ::DWORD service_ar);
        bool store_service_handle(const str::xtype& service_name, ::DWORD service_ar);
        void aseert_SCM_access_right(::DWORD minimum_required_privileges);
        void throw_last_error(const std::string& message) const;
        static scm::status to_state(::DWORD state);
        ::SC_HANDLE get_SCM_handle()const;
        access_right_t get_SCM_access_right()const;
        ::SC_HANDLE get_service_handle(const str::xtype& service_name);
        bool get_service_handle(const str::xtype& service_name, ::DWORD service_ar, ::SC_HANDLE& out);
        void remove_service_handle(const str::xtype& service_name);

    private:
        using resource = os::software::service::resource<::SC_HANDLE>;

        bool set_service_handle(const str::xtype& service_name);
        bool set_service_handle(const str::xtype& service_name, std::unique_ptr<resource> ptr);
        bool generate_service_resource(const str::xtype& service_name, ::DWORD service_ar);

    private:
        const str::xtype mComputerName;
        using service_container = std::map<str::xtype, std::unique_ptr<resource>>;
        mutable std::pair<std::unique_ptr<resource>, access_right_t> mSCM_Info;
        mutable service_container mServices;
    };
}

namespace os::software::service
{
    scm::impl::impl(const str::xtype& computerName)
        : 
        logger_help("scm"),
        mComputerName(computerName)
    {
        try
        {
            aseert_SCM_access_right(SC_MANAGER_ALL_ACCESS);
        }
        catch(const std::system_error& e)
        {
            const auto& u8_str = encode::string::utf16_to_utf8(computerName);
            const auto& text = WLogText_A("{} 因为 {}.{}:{} 转为使用 READ 打开", u8_str, e.code().category().name(), e.code().value(), e.what());
            log_message(common::log::info, text);
            aseert_SCM_access_right(GENERIC_READ);
        }
        catch(const std::exception&)
        {
            std::rethrow_exception(std::current_exception());
        }
    }

    scm::impl::~impl()
    {}

    bool os::software::service::scm::impl::install(const str::xtype& binary_path, const str::xtype& display_name, bool auto_start)
    {
        log_message(common::log::trace, WLogText_A("install..."));
        const auto& utf8_path = encode::string::utf16_to_utf8(binary_path);
        const auto& utf8_name = encode::string::utf16_to_utf8(display_name);
        try
        {
            aseert_SCM_access_right(SC_MANAGER_CREATE_SERVICE);
        }
        catch(const std::system_error& e)
        {
            const auto& text = WLogText_A("failed to install {}.{} {}.{}:{}", utf8_name, utf8_path, 
                                                                              e.code().category().name(),
                                                                              e.code().value(), e.what());
            log_message(common::log::err, text);
            return false;
        }
        catch(const std::exception& e)
        {
            const auto& text = WLogText_A("failed to install {}.{} {}.{}", utf8_name, utf8_path, ::GetLastError(), e.what());
            log_message(common::log::exception, text);
            return false;
        }

        bool install_ok{ false };
        do
        {
            ::DWORD start = SERVICE_DEMAND_START;
            if(auto_start)
            {
                start = SERVICE_AUTO_START;
            }
            
            auto create_result = std::make_unique<resource>(::CreateService(get_SCM_handle(), display_name.c_str(), display_name.c_str(),
                                                                            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, start,
                                                                            SERVICE_ERROR_NORMAL, binary_path.c_str(),
                                                                            nullptr, nullptr, nullptr, nullptr, nullptr));
            if(NULL == *create_result)
            {
                const auto& text = WLogText_A("failed to install {}.{}.{}", utf8_name, utf8_path, ::GetLastError());
                log_message(common::log::err, text);
                break;
            }

            install_ok = set_service_handle(display_name, std::move(create_result));

        } while(0);

        return install_ok;
    }

    bool scm::impl::uninstall(const str::xtype& service_name)
    {
        log_message(common::log::trace, WLogText_A("uninstall..."));
        ::BOOL no_err{ TRUE };
        ::SC_HANDLE dest_handle{ NULL };
        do
        {
            if(is_exist(service_name))
            {
                if(status::kStopped != get_status(service_name))
                {
                    if(false == stop(service_name))
                    {
                        no_err = FALSE;
                        break;
                    }
                }
            }

            if(get_service_handle(service_name, DELETE, dest_handle))
            {
                no_err = ::DeleteService(dest_handle);
            }

        } while(0);

        if(FALSE == no_err)
        {
            const auto& u8_str = encode::string::utf16_to_utf8(service_name);
            const auto& text = WLogText_A("failed to uninstall {}.{}.{}", u8_str, static_cast<void*>(dest_handle), ::GetLastError());
            log_message(common::log::err, text);
        }
        else
        {
            remove_service_handle(service_name);
            log_message(common::log::trace, WLogText_A("uninstall successed"));
        }
        return no_err == TRUE;
    }

    bool scm::impl::start(const str::xtype& service_name)
    {
        log_message(common::log::trace, WLogText_A("start..."));
        ::BOOL no_err{ FALSE };
        ::SC_HANDLE dest_handle{ NULL };
        if(get_service_handle(service_name, SERVICE_START, dest_handle))
        {
            no_err = ::StartService(dest_handle, 0, NULL);
        }

        if(FALSE == no_err)
        {
            const auto& u8_str = encode::string::utf16_to_utf8(service_name);
            const auto& text = WLogText_A("failed to start {}.{}.{}", u8_str, static_cast<void*>(dest_handle), ::GetLastError());
            log_message(common::log::err, text);
        }
        else
            log_message(common::log::trace, WLogText_A("start successed..."));

        return no_err == TRUE;
    }

    bool scm::impl::stop(const str::xtype& service_name)
    {
        return do_control_service(service_name, SERVICE_STOP, SERVICE_CONTROL_STOP);
    }

    bool scm::impl::pause(const str::xtype& service_name)
    {
        return do_control_service(service_name, SERVICE_PAUSE_CONTINUE, SERVICE_CONTROL_PAUSE);
    }

    bool scm::impl::cancel_pause(const str::xtype& service_name)
    {
        return do_control_service(service_name, SERVICE_PAUSE_CONTINUE, SERVICE_CONTROL_CONTINUE);
    }

    bool scm::impl::do_control_service(const str::xtype& service_name, DWORD access, DWORD dwControl)
    {
        log_message(common::log::trace, WLogText_A("do {}...", dwControl));
        ::BOOL no_err{ FALSE };
        ::SC_HANDLE dest_handle{ NULL };
        if(get_service_handle(service_name, access, dest_handle))
        {
            ::SERVICE_STATUS status{};
            no_err = ::ControlService(dest_handle, dwControl, &status);
        }

        const auto& u8_str = encode::string::utf16_to_utf8(service_name);
        if(FALSE == no_err)
        {
            const auto& text = WLogText_A("failed to {}.{}.{}.{}.{}", u8_str, dwControl, access, static_cast<void*>(dest_handle), ::GetLastError());
            log_message(common::log::err, text);
        }
        else
        {
            const auto& text = WLogText_A("control {}.{} success", u8_str, dwControl);
            log_message(common::log::info, text);
        }

        return no_err == TRUE;
    }

    scm::status scm::impl::get_status(const str::xtype& service_name)
    {
        log_message(common::log::trace, WLogText("get status {}...", service_name));
        ::SERVICE_STATUS_PROCESS status{};
        ::SC_HANDLE dest_handle{ NULL };
        do
        {
            if(false == get_service_handle(service_name, SERVICE_QUERY_STATUS, dest_handle))
                break;

            ::DWORD bytesNeeded{ 0 };
            if(FALSE == ::QueryServiceStatusEx(dest_handle, SC_STATUS_PROCESS_INFO,
                                               reinterpret_cast<::LPBYTE>(&status), sizeof(status), &bytesNeeded))
            {
                const auto& u8_str = encode::string::utf16_to_utf8(service_name);
                const auto& text = WLogText_A("failed to query {} status. {}.{}", u8_str, static_cast<void*>(dest_handle), ::GetLastError());
                log_message(common::log::err, text);
            }

        } while(0);

        return to_state(status.dwCurrentState);
    }

    bool scm::impl::set_start_type(const str::xtype& service_name, ::DWORD startType)
    {
        ::BOOL no_err{ FALSE };
        ::SC_HANDLE dest_handle{ NULL };

        if(get_service_handle(service_name, SERVICE_CHANGE_CONFIG, dest_handle))
        {
            no_err = ::ChangeServiceConfig(dest_handle, SERVICE_NO_CHANGE, startType, SERVICE_NO_CHANGE,
                                           nullptr, nullptr, nullptr, nullptr, nullptr,
                                           nullptr, nullptr);
        }

        if(FALSE == no_err)
        {
            const auto& u8_str = encode::string::utf16_to_utf8(service_name);
            const auto& text = WLogText_A("failed to change {} start type. {}.{}", u8_str, static_cast<void*>(dest_handle), ::GetLastError());
            log_message(common::log::err, text);
        }

        return no_err == TRUE;
    }

    bool scm::impl::set_description(const str::xtype& service_name, const str::xtype& description)
    {
        ::BOOL no_err{ FALSE };
        ::SC_HANDLE dest_handle{ NULL };
        if(get_service_handle(service_name, SERVICE_CHANGE_CONFIG, dest_handle))
        {
            ::SERVICE_DESCRIPTION desc{ const_cast<::LPTSTR>(description.c_str()) };
            no_err = ::ChangeServiceConfig2(dest_handle, SERVICE_CONFIG_DESCRIPTION, &desc);
        }

        if(FALSE == no_err)
        {
            const auto& u8_str = encode::string::utf16_to_utf8(service_name);
            const auto& text = WLogText_A("failed to set {} description. {}.{}", u8_str, static_cast<void*>(dest_handle), ::GetLastError());
            log_message(common::log::err, text);
        }

        return no_err == TRUE;
    }

    bool scm::impl::is_exist(const str::xtype& service_name)
    {
        const auto& iter = mServices.find(service_name);
        if(iter != mServices.cend())
        {
            return true;
        }

        return open_service_and_store(service_name, GENERIC_READ);
        ; ERROR_SERVICE_DOES_NOT_EXIST;
        auto open_result = ::OpenService(get_SCM_handle(), service_name.c_str(), GENERIC_READ);
        return false;
    }

    str::xtype scm::impl::get_display_name(const str::xtype& service_name)
    {
        ::SC_HANDLE dest_handle{NULL};
        if(false == get_service_handle(service_name, SERVICE_QUERY_CONFIG, dest_handle))
            return str::xtype{ TEXT("") };

        ::DWORD bytes_needed = 0;
        auto result = ::QueryServiceConfig(dest_handle, nullptr, 0, &bytes_needed);
        if(FALSE == result && ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            const auto& u8_str = encode::string::utf16_to_utf8(service_name);
            const auto& text = WLogText_A("failed to query {} config size. {}.{}", u8_str, static_cast<void*>(dest_handle), ::GetLastError());
            log_message(common::log::err, text);
        }

        std::vector<std::uint8_t> buffer(bytes_needed, 0);
        auto config = reinterpret_cast<::LPQUERY_SERVICE_CONFIG>(buffer.data());
        if(0 == ::QueryServiceConfig(dest_handle, config, bytes_needed, &bytes_needed))
        {
            const auto& u8_str = encode::string::utf16_to_utf8(service_name);
            const auto& text = WLogText_A("failed to query {} config. {}.{}", u8_str, static_cast<void*>(dest_handle), ::GetLastError());
            log_message(common::log::err, text);
        }

        return config->lpDisplayName;
    }

    bool scm::impl::open_service_and_store(const str::xtype& service_name, ::DWORD service_ar)
    {
        const auto& u8_str = encode::string::utf16_to_utf8(service_name);
        try
        {
            access_right_t scm_ar;
            if(false == get_scm_ar_by_service_ar(*this, service_ar, scm_ar))
            {
                return false;
            }

            aseert_SCM_access_right(scm_ar);
        }
        catch(const std::system_error& e)
        {
            const auto& text = WLogText_A("failed to open {}.{} {}.{}:{}", u8_str, service_ar, e.code().category().name(), e.code().value(), e.what());
            log_message(common::log::err, text);
            return false;
        }
        catch(const std::exception& e)
        {
            const auto& text = WLogText_A("failed to open {}.{}:{}", u8_str, service_ar, e.what());
            log_message(common::log::exception, text);
            return false;
        }

        bool no_err = false;
        if(false == generate_service_resource(service_name, SERVICE_ALL_ACCESS))
        {
            no_err = generate_service_resource(service_name, service_ar);
        }
        else
        {
            no_err = true;
        }
        return no_err;

        //do
        //{
        //    //auto do_success = [&](::SC_HANDLE newHandle)
        //    //    {
        //    //        auto iter = mServices.find(service_name);
        //    //        if(iter == mServices.end())
        //    //        {
        //    //            auto iter = mServices.emplace(service_name, nullptr);
        //    //            if(iter.second)
        //    //            {
        //    //                auto create_result = std::make_unique<resource>(newHandle);
        //    //                iter.first->second.swap(create_result);
        //    //            }
        //    //        }
        //    //        else if(iter->second->get_copy() != newHandle)
        //    //        {
        //    //        }
        //    //        no_err = true;
        //    //    };
        //} while(0);

        //return no_err;
    }

    void scm::impl::aseert_SCM_access_right(::DWORD minimum_required_privileges)
    {
        do
        {
            if(SC_MANAGER_ALL_ACCESS == mSCM_Info.second && mSCM_Info.first)
            {
                break;
            }

            const auto& iter = kSCM_AR_generic_level.find(minimum_required_privileges);
            if(minimum_required_privileges == mSCM_Info.second && mSCM_Info.first)
            {
                break;
            }

            ::DWORD highest_privileges = SC_MANAGER_ALL_ACCESS;
            auto computer = mComputerName.empty() ? nullptr : mComputerName.c_str();
            mSCM_Info.first = std::make_unique<resource>(::OpenSCManager(computer,
                                                                         nullptr,
                                                                         highest_privileges));

            if(mSCM_Info.first)
            {
                mSCM_Info.second = highest_privileges;
                break;
            }

            if(iter == kSCM_AR_generic_level.cend())
            {
                highest_privileges = minimum_required_privileges;
            }
            else
            {
                highest_privileges = iter->second;
            }

            mSCM_Info.first = std::make_unique<resource>(::OpenSCManager(computer, nullptr, highest_privileges));

            assert(NULL != (*mSCM_Info.first));
            if(NULL == (*mSCM_Info.first))
            {
                throw_last_error(" failed to open service control manager");
            }

        } while(0);

    }

    void scm::impl::throw_last_error(const std::string& message) const
    {
        throw std::system_error(static_cast<int>(GetLastError()),
                                std::system_category(),
                                message
        );
    }

    scm::status scm::impl::to_state(::DWORD state)
    {
        switch(state)
        {
        case SERVICE_STOPPED:          return scm::status::kStopped;
        case SERVICE_START_PENDING:    return scm::status::kStarting;
        case SERVICE_STOP_PENDING:     return scm::status::kStopping;
        case SERVICE_RUNNING:          return scm::status::kRunning;
        case SERVICE_CONTINUE_PENDING: return scm::status::kContinuing;
        case SERVICE_PAUSE_PENDING:    return scm::status::kPausing;
        case SERVICE_PAUSED:           return scm::status::kPaused;
        default:                       return scm::status::kUnknown;
        }
    }

    ::SC_HANDLE scm::impl::get_SCM_handle() const
    {
        return mSCM_Info.first->get_copy();
    }

    access_right_t scm::impl::get_SCM_access_right() const
    {
        return mSCM_Info.second;
    }

    ::SC_HANDLE scm::impl::get_service_handle(const str::xtype& service_name)
    {
        const auto& iter = mServices.find(service_name);
        return iter != mServices.cend() ? iter->second->get_copy() : NULL;
    }

    bool scm::impl::get_service_handle(const str::xtype& service_name, ::DWORD service_ar, ::SC_HANDLE& out)
    {
        log_message(common::log::trace, WLogText("get handle"));
        out = get_service_handle(service_name);
        if(NULL == out)
        {
            if(false == open_service_and_store(service_name, service_ar))
                out = get_service_handle(service_name);
        }

        return out != NULL;
    }

    void scm::impl::remove_service_handle(const str::xtype& service_name)
    {
        auto iter = mServices.begin();
        while(iter != mServices.end())
        {
            if(iter->first == service_name)
            {
                iter->second.reset();
                mServices.erase(iter);
                break;
            }
            ++iter;
        }
    }

    bool scm::impl::set_service_handle(const str::xtype& service_name)
    {
        //auto iter = mServices.emplace(service_name, nullptr);
        //if(iter.second)
        //{
        //    iter.first->second.swap(create_result);
        //    log_message(common::log::trace, WLogText_A("install successed {}", auto_start));
        //}
        //else
        //{
        //    const auto& text = WLogText_A("failed to stored {}.{}", utf8_name, utf8_path);
        //    log_message(common::log::err, text);
        //}
        return false;
    }

    bool scm::impl::set_service_handle(const str::xtype& service_name, std::unique_ptr<resource> ptr)
    {
        if(nullptr == ptr->get_copy())
        {
            log_message(common::log::err, WLogText("failed to stored {} is invalid", service_name));
            return false;
        }

        bool no_err{ false };
        try
        {
            auto iter = mServices.emplace(service_name, nullptr);
            if(iter.second)
            {
                iter.first->second.swap(ptr);
                no_err = true;
            }
            else
            {
                auto count = mServices.count(service_name);
                log_message(common::log::err, WLogText("failed to stored {}.{}", count, service_name));
            }
        }
        catch(const std::exception& e)
        {
            const auto& utf8_name = encode::string::utf16_to_utf8(service_name);
            log_message(common::log::err, WLogText_A("failed to stored {} exc {}", utf8_name, e.what()));
        }

        return no_err;
    }

    bool scm::impl::generate_service_resource(const str::xtype& service_name, ::DWORD service_ar)
    {
        bool no_err = false;
        do
        {
            auto do_success = [&](::SC_HANDLE newHandle)
                {
                    auto create_result = std::make_unique<resource>(newHandle);
                    return set_service_handle(service_name, std::move(create_result));
                };

            auto open_result = ::OpenService(get_SCM_handle(), service_name.c_str(), SERVICE_ALL_ACCESS);
            if(open_result)
            {
                no_err = do_success(open_result);
                break;
            }


            open_result = ::OpenService(get_SCM_handle(), service_name.c_str(), service_ar);
            if(open_result)
            {
                no_err = do_success(open_result);
            }
            else
            {
                const auto& utf8_name = encode::string::utf16_to_utf8(service_name);
                log_message(common::log::err, WLogText_A("failed to open {}.{} {}", utf8_name, service_ar, ::GetLastError()));
            }

        } while(0);

        return no_err;
    }
}

namespace os::software::service
{
    scm::scm(const str::xtype& computerName)
        : mImpl(std::make_unique<impl>(computerName))
    {}

    scm::~scm()
    {}

    bool scm::install(const str::xtype& binaryPath, const str::xtype& displayName, bool auto_start)
    {
        return mImpl->install(binaryPath, displayName, auto_start);
    }

    bool scm::uninstall(const str::xtype& service_name)
    {
        return mImpl->uninstall(service_name);
    }

    bool scm::start(const str::xtype& service_name)
    {
        return mImpl->start(service_name);
    }

    bool scm::stop(const str::xtype& service_name)
    {
        return mImpl->stop(service_name);
    }

    bool scm::pause(const str::xtype& service_name)
    {
        return mImpl->pause(service_name);
    }

    bool scm::cancel_pause(const str::xtype& service_name)
    {
        return mImpl->cancel_pause(service_name);
    }

    bool scm::is_this_status(const str::xtype& service_name, status& that)
    {
        const auto& now = mImpl->get_status(service_name);
        if(that == now)
        {
            return true;
        }

        mImpl->log_message(common::log::trace, WLogText("{} status = {}", service_name, static_cast<int>(now)));
        that = now;
        return false;
    }

    bool scm::is_exist(const str::xtype& service_name)
    {
        return mImpl->is_exist(service_name);
    }

    scm::status scm::get_status(const str::xtype& service_name) const
    {
        return mImpl->get_status(service_name);
    }

    str::xtype scm::get_display_name(const str::xtype& service_name) const
    {
        return mImpl->get_display_name(service_name);
    }

    bool scm::set_description(const str::xtype& service_name, const str::xtype& description)
    {
        return mImpl->set_description(service_name, description);
    }

    bool scm::set_start_type(const str::xtype& service_name, unsigned long startType)
    {
        return mImpl->set_start_type(service_name, startType);
    }
}