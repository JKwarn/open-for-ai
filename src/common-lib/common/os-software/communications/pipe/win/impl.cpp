#include "../pipe.h"
#include <windows.h>
#include <chrono>

namespace communications::pipe
{


}



//
//// communications::pipe::Impl 的定义
//namespace communications
//{
//// RAII 句柄包装器
//    struct HandleDeleter
//    {
//        void operator()(::HANDLE h) const noexcept
//        {
//            if(h != INVALID_HANDLE_VALUE)
//            {
//                CloseHandle(h);
//            }
//        }
//    };
//    using ScopedHandle = std::unique_ptr<void, HandleDeleter>;
//
//    // PIMPL 实现类
//    class pipe::impl
//    {
//    public:
//        enum class type_t
//        {
//            Anonymous, NamedServer, NamedClient
//        };
//
//        // 类型别名简化
//        template <typename T>
//        using result = std::expected<T, pipe_error>;
//        using result_t = result<std::unique_ptr<pipe::impl>>;
//
//        type_t mType;
//
//        // 匿名管道句柄
//        struct
//        {
//            ::HANDLE read = INVALID_HANDLE_VALUE;
//            ::HANDLE write = INVALID_HANDLE_VALUE;
//        } anonymous;
//
//        // 命名管道句柄
//        struct
//        {
//            ::HANDLE handle = INVALID_HANDLE_VALUE;
//            std::wstring name;
//        } named;
//
//        ~impl();
//
//        //=== 核心方法实现 ============================================
//        static result_t create_anonymous();
//        static result_t create_named(std::wstring_view name, bool is_server);
//
//        void_result_t connect(std::uint32_t timeout_ms);
//
//        result<std::size_t> read(void* buffer, std::size_t size, std::uint32_t timeout_ms);
//        result<std::size_t> write(std::string_view data);
//
//        void close();
//    };
//};
//
//// communications::pipe::impl 的实现
//namespace communications
//{
//    pipe::impl::~impl()
//    {
//        close();
//    }
//
//    //=== 核心方法实现 ============================================
//    pipe::impl::result_t pipe::impl::create_anonymous()
//    {
//        ::SECURITY_ATTRIBUTES sa;
//        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
//        sa.bInheritHandle = FALSE;
//        sa.lpSecurityDescriptor = nullptr;
//
//        ::HANDLE hRead{NULL};
//        ::HANDLE hWrite{NULL};
//
//        if(FALSE == ::CreatePipe(&hRead, &hWrite, &sa, 0))
//        {
//            return std::unexpected(pipe_error::CreationFailed);
//        }
//
//        auto obj = std::make_unique<impl>();
//        obj->mType = type_t::Anonymous;
//        obj->anonymous.read = hRead;
//        obj->anonymous.write = hWrite;
//        return obj;
//    }
//
//    pipe::impl::result_t pipe::impl::create_named(std::wstring_view name, bool is_server)
//    {
//        auto obj = std::make_unique<impl>();
//        obj->named.name = name;
//
//        if(is_server)
//        {
//            obj->mType = type_t::NamedServer;
//            obj->named.handle = ::CreateNamedPipe(name.data(),
//                                                  PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
//                                                  PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
//                                                  PIPE_UNLIMITED_INSTANCES,
//                                                  4096,
//                                                  4096, 
//                                                  0, 
//                                                  nullptr
//            );
//
//            if(obj->named.handle == INVALID_HANDLE_VALUE)
//            {
//                return std::unexpected(pipe_error::CreationFailed);
//            }
//        }
//        else
//        {
//            obj->mType = type_t::NamedClient;
//        }
//
//        return obj;
//    }
//
//    pipe::void_result_t pipe::impl::connect(std::uint32_t timeout_ms)
//    {
//        if(mType != type_t::NamedClient)
//        {
//            return std::unexpected(pipe_error::InvalidHandle);
//        }
//
//        ::HANDLE hPipe = ::CreateFile(named.name.c_str(),
//                                      GENERIC_READ | GENERIC_WRITE,
//                                      0, 
//                                      nullptr, 
//                                      OPEN_EXISTING, 
//                                      FILE_FLAG_OVERLAPPED, 
//                                      nullptr
//        );
//
//        if(hPipe == INVALID_HANDLE_VALUE)
//        {
//            if(::GetLastError() == ERROR_PIPE_BUSY)
//            {
//                if(FALSE == ::WaitNamedPipe(named.name.c_str(), timeout_ms))
//                {
//                    return std::unexpected(pipe_error::Timeout);
//                }
//                hPipe = ::CreateFile(named.name.c_str(),
//                                     GENERIC_READ | GENERIC_WRITE,
//                                     0,
//                                     nullptr,
//                                     OPEN_EXISTING,
//                                     FILE_FLAG_OVERLAPPED,
//                                     nullptr
//                );
//            }
//        }
//
//        if(hPipe == INVALID_HANDLE_VALUE)
//        {
//            return std::unexpected(pipe_error::ConnectionFailed);
//        }
//
//        named.handle = hPipe;
//        return {};
//    }
//
//    pipe::impl::result<std::size_t> pipe::impl::read(void* buffer, std::size_t size, std::uint32_t timeout_ms)
//    {
//        ::HANDLE hRead = (mType == type_t::Anonymous) ?
//            anonymous.read : named.handle;
//
//        ::OVERLAPPED ov{};
//        ov.hEvent = ::CreateEvent(nullptr, TRUE, FALSE, nullptr);
//        if(!ov.hEvent) 
//            return std::unexpected(pipe_error::UnknownError);
//
//        DWORD bytesRead = 0;
//        if(FALSE == ::ReadFile(hRead, buffer, size, &bytesRead, &ov))
//        {
//            if(::GetLastError() != ERROR_IO_PENDING)
//            {
//                ::CloseHandle(ov.hEvent);
//                return std::unexpected(pipe_error::ReadFailed);
//            }
//
//            DWORD waitResult = ::WaitForSingleObject(ov.hEvent, timeout_ms);
//            if(waitResult == WAIT_TIMEOUT)
//            {
//                ::CancelIo(hRead);
//                ::CloseHandle(ov.hEvent);
//                return std::unexpected(pipe_error::Timeout);
//            }
//            else if(waitResult != WAIT_OBJECT_0)
//            {
//                ::CloseHandle(ov.hEvent);
//                return std::unexpected(pipe_error::ReadFailed);
//            }
//
//            if(FALSE == ::GetOverlappedResult(hRead, &ov, &bytesRead, FALSE))
//            {
//                ::CloseHandle(ov.hEvent);
//                return std::unexpected(pipe_error::ReadFailed);
//            }
//        }
//
//        ::CloseHandle(ov.hEvent);
//        return bytesRead;
//    }
//
//    pipe::impl::result<std::size_t> pipe::impl::write(std::string_view data)
//    {
//        ::HANDLE hWrite = (mType == type_t::Anonymous) ? anonymous.write : named.handle;
//
//        ::DWORD bytesWritten = 0;
//        if(FALSE == ::WriteFile(hWrite, data.data(), data.size(), &bytesWritten, nullptr))
//        {
//            return std::unexpected(pipe_error::WriteFailed);
//        }
//        return bytesWritten;
//    }
//
//    void pipe::impl::close()
//    {
//        if(mType == type_t::Anonymous)
//        {
//            if(anonymous.read != INVALID_HANDLE_VALUE)
//            {
//                ::CloseHandle(anonymous.read);
//                anonymous.read = INVALID_HANDLE_VALUE;
//            }
//            if(anonymous.write != INVALID_HANDLE_VALUE)
//            {
//                ::CloseHandle(anonymous.write);
//                anonymous.write = INVALID_HANDLE_VALUE;
//            }
//        }
//        else
//        {
//            if(named.handle != INVALID_HANDLE_VALUE)
//            {
//                ::CloseHandle(named.handle);
//                named.handle = INVALID_HANDLE_VALUE;
//            }
//        }
//    }
//
//}



//=== 通用工具 ================================
namespace communications::pipe_detail
{
    struct handle_deleter
    {
        void operator()(::HANDLE h) noexcept
        {
            if(h != INVALID_HANDLE_VALUE) 
                ::CloseHandle(h);
        }
    };
    using scoped_resource_t = std::unique_ptr<void, handle_deleter>;
    using error_code_t = communications::pipe::error_code;
    error_code_t last_error() noexcept
    {
        switch(::GetLastError())
        {
        case ERROR_SUCCESS:         return error_code_t::success;
        case ERROR_ACCESS_DENIED:   return error_code_t::access_denied;
        case ERROR_PIPE_BUSY: [[fallthrough]];
        case ERROR_TIMEOUT:         return error_code_t::timeout;
        default:                    return error_code_t::unknown_error;
        }
    }
} // namespace detail



// communications::pipe::server::impl 的声明
namespace communications::pipe
{
    namespace detail = pipe_detail;
    class server::impl
    {
    public:
        static result<std::unique_ptr<impl>> create(std::wstring_view name);
        result<std::size_t> read(void* buffer, std::size_t size, std::uint32_t timeout_ms);
        result<std::size_t> write(std::string_view data);
        void close();
    private:
        detail::scoped_resource_t mResource;
        std::wstring name;
    };
}

// communications::pipe::server::impl 的实现
namespace communications::pipe
{
    result<std::unique_ptr<server::impl>> pipe::server::impl::create(std::wstring_view name)
    {
        auto h = ::CreateNamedPipe(name.data(),
                                   PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                   PIPE_UNLIMITED_INSTANCES,
                                   4096, 
                                   4096, 
                                   0, 
                                   nullptr
        );

        if(h == INVALID_HANDLE_VALUE)
        {
            return std::unexpected(detail::last_error());
        }

        auto p = std::make_unique<impl>();
        p->mResource.reset(h);
        p->name = name;
        return p;
    }

    result<std::size_t> server::impl::read(void* buffer, std::size_t size, std::uint32_t timeout_ms)
    {
        ::OVERLAPPED ov{};
        ov.hEvent = ::CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if(!ov.hEvent) 
            return std::unexpected(error_code::unknown_error);

        ::DWORD bytes_read = 0;
        if(FALSE == ::ReadFile(mResource.get(), buffer, size, &bytes_read, &ov))
        {
            if(::GetLastError() != ERROR_IO_PENDING)
            {
                return std::unexpected(error_code::read_failed);
            }

            ::DWORD wait_result = ::WaitForSingleObject(ov.hEvent, timeout_ms);
            if(wait_result == WAIT_TIMEOUT)
            {
                ::CancelIo(mResource.get());
                return std::unexpected(error_code::timeout);
            }
            if(FALSE == ::GetOverlappedResult(mResource.get(), &ov, &bytes_read, FALSE))
            {
                return std::unexpected(error_code::read_failed);
            }
        }
        return bytes_read;
    }

    result<std::size_t> server::impl::write(std::string_view data)
    {
        ::DWORD bytes_written = 0;
        if(FALSE == ::WriteFile(mResource.get(), data.data(), data.size(), &bytes_written, nullptr))
        {
            return std::unexpected(error_code::write_failed);
        }
        return bytes_written;
    }

    void server::impl::close()
    {
        mResource.reset();
    }

}



// communications::pipe::client::impl 的声明
namespace communications::pipe
{
    class client::impl
    {
    public:
        static result<std::unique_ptr<impl>> connect(std::wstring_view name, std::uint32_t timeout_ms);

    private:
        detail::scoped_resource_t mResource;
        // 读取/写入实现与服务端类似（略）
    };
}

// communications::pipe::client::impl 的定义
namespace communications::pipe
{
    result<std::unique_ptr<client::impl>> client::impl::connect(std::wstring_view name, std::uint32_t timeout_ms)
    {
        ::HANDLE h = ::CreateFile(name.data(),
                                  GENERIC_READ | GENERIC_WRITE,
                                  0, 
                                  nullptr, 
                                  OPEN_EXISTING, 
                                  FILE_FLAG_OVERLAPPED, 
                                  nullptr
        );

        if(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY)
        {
            if(FALSE == WaitNamedPipe(name.data(), timeout_ms))
            {
                return std::unexpected(error_code::timeout);
            }

            h = ::CreateFile(name.data(),
                             GENERIC_READ | GENERIC_WRITE,
                             0,
                             nullptr,
                             OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED,
                             nullptr
            );
        }

        if(h == INVALID_HANDLE_VALUE)
        {
            return std::unexpected(detail::last_error());
        }

        auto p = std::make_unique<impl>();
        p->mResource.reset(h);
        return p;
    }
}

// 匿名管道
namespace communications::pipe
{
    result<std::pair<client, server>> create_anonymous()
    {
        ::SECURITY_ATTRIBUTES sa{ sizeof(::SECURITY_ATTRIBUTES), nullptr, FALSE };
        ::HANDLE hRead{nullptr};
        ::HANDLE hWrite{nullptr};

        if(FALSE == ::CreatePipe(&hRead, &hWrite, &sa, 0))
        {
            return std::unexpected(detail::last_error());
        }

        auto client_obj = std::make_unique<client::impl>();
        //client_obj->handle.reset(hRead);

        auto server_obj = std::make_unique<server::impl>();
        //server_obj->handle.reset(hWrite);


        return std::pair{ client{ std::move(client_obj) },
                          server{ std::move(server_obj) } };
    }
}