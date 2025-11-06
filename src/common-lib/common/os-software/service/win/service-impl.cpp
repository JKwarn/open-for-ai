#include <wtsapi32.h>
#include <string>
#include <format>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")

namespace os::services 
{
    class windows_service::impl 
    {
    public:
        impl(std::wstring_view name)
            : name_(name),
            status_handle_(nullptr),
            current_state_(state::stopped)
        {
        }

        ~impl() {
            if(status_handle_) {
                report_status(SERVICE_STOPPED);
            }
        }

        void start() {
            SERVICE_TABLE_ENTRYW dispatch_table[] = 
            {
                { const_cast<LPWSTR>(name_.c_str()), service_main },
                { nullptr, nullptr }
            };

            if(!StartServiceCtrlDispatcherW(dispatch_table)) {
                throw std::system_error(
                    GetLastError(),
                    std::system_category(),
                    "Failed to start service control dispatcher"
                );
            }
        }


    private:
        static void WINAPI service_main(DWORD argc, LPWSTR* argv) {
            instance->service_main_impl(argc, argv);
        }

        void service_main_impl(DWORD argc, LPWSTR* argv) {
            status_handle_ = RegisterServiceCtrlHandlerExW(
                name_.c_str(),
                control_handler,
                nullptr
            );

            if(!status_handle_) {
                throw std::system_error(
                    GetLastError(),
                    std::system_category(),
                    "Failed to register service control handler"
                );
            }

            report_status(SERVICE_START_PENDING);
            report_status(SERVICE_RUNNING);
        }

        static DWORD WINAPI control_handler(
            DWORD control,
            DWORD event_type,
            LPVOID event_data,
            LPVOID context
        ) {
            return instance->control_handler_impl(
                control,
                event_type,
                event_data
            );
        }

        DWORD control_handler_impl(
            DWORD control,
            DWORD event_type,
            LPVOID event_data
        ) {
            switch(control) {
            case SERVICE_CONTROL_STOP:
                return NO_ERROR;
            case SERVICE_CONTROL_PAUSE:
                return NO_ERROR;
            case SERVICE_CONTROL_CONTINUE:
                return NO_ERROR;
            case SERVICE_CONTROL_INTERROGATE:
                return NO_ERROR;
            default:
                if(control >= 128 && control <= 255) {
                }
                return ERROR_CALL_NOT_IMPLEMENTED;
            }
        }

        void report_status(DWORD state) {
            SERVICE_STATUS status = {
                .dwServiceType = SERVICE_WIN32_OWN_PROCESS,
                .dwCurrentState = state,
                .dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                     SERVICE_ACCEPT_PAUSE_CONTINUE,
                .dwWin32ExitCode = NO_ERROR,
                .dwServiceSpecificExitCode = 0,
                .dwCheckPoint = 0,
                .dwWaitHint = 3000
            };

            if(!SetServiceStatus(status_handle_, &status)) {
                throw std::system_error(
                    GetLastError(),
                    std::system_category(),
                    "Failed to set service status"
                );
            }
        }

        std::wstring name_;
        SERVICE_STATUS_HANDLE status_handle_;
        state current_state_;
        //control_handler handler_;

        static windows_service::impl* instance;
    };

    windows_service::impl* windows_service::impl::instance = nullptr;

    windows_service::windows_service(std::wstring_view name)
        : pimpl_(std::make_unique<impl>(name)) {
    }

    windows_service::~windows_service() = default;

    void windows_service::start() { pimpl_->start(); }
    void windows_service::install(
        std::wstring_view service_name,
        std::wstring_view display_name,
        DWORD start_type
    ) {
        SC_HANDLE scm = OpenSCManagerW(
            nullptr,
            nullptr,
            SC_MANAGER_CREATE_SERVICE
        );

        if(!scm) {
            throw std::system_error(
                GetLastError(),
                std::system_category(),
                "Failed to open service control manager"
            );
        }

        std::wstring path(MAX_PATH, L'\0');
        GetModuleFileNameW(nullptr, path.data(), MAX_PATH);

        SC_HANDLE service = CreateServiceW(
            scm,
            service_name.data(),
            display_name.data(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            start_type,
            SERVICE_ERROR_NORMAL,
            path.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr
        );

        if(!service) {
            CloseServiceHandle(scm);
            throw std::system_error(
                GetLastError(),
                std::system_category(),
                std::format("Failed to create service {}", service_name)
            );
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
    }

    void windows_service::uninstall(std::wstring_view service_name) {
        SC_HANDLE scm = OpenSCManagerW(
            nullptr,
            nullptr,
            SC_MANAGER_CONNECT
        );

        if(!scm) {
            throw std::system_error(
                GetLastError(),
                std::system_category(),
                "Failed to open service control manager"
            );
        }

        SC_HANDLE service = OpenServiceW(
            scm,
            service_name.data(),
            DELETE
        );

        if(!service) {
            CloseServiceHandle(scm);
            throw std::system_error(
                GetLastError(),
                std::system_category(),
                std::format("Failed to open service {}", service_name)
            );
        }

        if(!DeleteService(service)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            throw std::system_error(
                GetLastError(),
                std::system_category(),
                std::format("Failed to delete service {}", service_name)
            );
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
    }
} // namespace os::services