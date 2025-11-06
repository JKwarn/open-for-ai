#pragma once
#include <memory>
#include <expected>
#include <string_view>
#include <string>
//
//namespace communications
//{
//    enum class pipe_error
//    {
//        CreationFailed,
//        ConnectionFailed,   // 名管道连接错误
//        ReadFailed,
//        WriteFailed,
//        InvalidHandle,
//        AccessDenied,
//        Timeout,
//        UnknownError
//    };
//
//
//    class pipe
//    {
//    public:
//        template <typename T>
//        using result_t = std::expected<T, pipe_error>;
//        using void_result_t = result_t<void>;
//        static result_t<pipe> create_anonymous();
//        static result_t<pipe> create_named(std::wstring_view name, bool is_server = true);
//        void_result_t connect(uint32_t timeout_ms = 0);
//        result_t<size_t> read(void* buffer, size_t size);
//        result_t<size_t> read(void* buffer, size_t size, uint32_t timeout_ms);
//        result_t<size_t> write(std::string_view data);
//        void close();
//        pipe(pipe&&) noexcept;
//        pipe& operator=(pipe&&) noexcept;
//        ~pipe();
//
//        pipe(const pipe&) = delete;
//        pipe& operator=(const pipe&) = delete;
//
//    private:
//        class impl;
//        std::unique_ptr<impl> pimpl;
//        explicit pipe(std::unique_ptr<impl> impl);
//    };
//}


namespace communications::pipe
{
    enum class error_code
    {
        success,
        creation_failed,
        connection_failed,
        read_failed,
        write_failed,
        invalid_handle,
        timeout,
        access_denied,
        unknown_error
    };

    template <typename T>
    using result = std::expected<T, error_code>;
    using void_result = result<void>;

    //=== 前置声明 ================================
    class server;
    class client;

    //=== 匿名管道 ================================
    result<std::pair<client, server>> create_anonymous();

    //=== 命名管道服务端 ==========================
    class server
    {
    public:
        static result<server> create_named(std::wstring_view name);
        result<size_t> read(void* buffer, size_t size);
        result<size_t> read(void* buffer, size_t size, uint32_t timeout_ms);
        result<size_t> write(std::string_view data);
        void close();

        server(server&&) noexcept;
        server& operator=(server&&) noexcept;
        ~server();

        server(const server&) = delete;
        server& operator=(const server&) = delete;

    private:
        class impl;
        std::unique_ptr<impl> pimpl;
        explicit server(std::unique_ptr<impl> impl);
        friend result<std::pair<client, server>> create_anonymous();
    };

    //=== 命名管道客户端 ==========================
    class client
    {
    public:
        static result<client> connect(std::wstring_view name, uint32_t timeout_ms = 0);
        result<size_t> read(void* buffer, size_t size);
        result<size_t> read(void* buffer, size_t size, uint32_t timeout_ms);
        result<size_t> write(std::string_view data);
        void close();

        client(client&&) noexcept;
        client& operator=(client&&) noexcept;
        client(const client&) = delete;
        client& operator=(const client&) = delete;
        ~client();

    private:
        class impl;
        std::unique_ptr<impl> pimpl;
        explicit client(std::unique_ptr<impl> impl);
        friend result<std::pair<client, server>> create_anonymous();
    };

}