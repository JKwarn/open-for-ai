#include "pipe.h"

#ifdef _WIN32

#include "./win/impl.cpp"

#endif // _WIN32

//namespace communications
//{
//    pipe::pipe(std::unique_ptr<impl> impl) : pimpl(std::move(impl))
//    {}
//
//    pipe::pipe(pipe&&) noexcept = default;
//    pipe& pipe::operator=(pipe&&) noexcept = default;
//    pipe::~pipe() = default;
//
//    pipe::result_t<pipe> pipe::create_anonymous()
//    {
//        auto impl = impl::create_anonymous();
//        if(!impl) return std::unexpected(impl.error());
//        return pipe(std::move(*impl));
//    }
//
//    pipe::result_t<pipe> pipe::create_named(std::wstring_view name, bool is_server)
//    {
//        auto impl = impl::create_named(name, is_server);
//        if(!impl) return std::unexpected(impl.error());
//        return pipe(std::move(*impl));
//    }
//
//    pipe::void_result_t pipe::connect(uint32_t timeout_ms)
//    {
//        return pimpl->connect(timeout_ms);
//    }
//
//    pipe::result_t<size_t> pipe::read(void* buffer, size_t size)
//    {
//        return pimpl->read(buffer, size, INFINITE);
//    }
//
//    pipe::result_t<size_t> pipe::read(void* buffer, size_t size, uint32_t timeout_ms)
//    {
//        return pimpl->read(buffer, size, timeout_ms);
//    }
//
//    pipe::result_t<size_t> pipe::write(std::string_view data)
//    {
//        return pimpl->write(data);
//    }
//
//    void pipe::close()
//    {
//        pimpl->close();
//    }
//}


namespace communications::pipe
{
    server::server(std::unique_ptr<impl> p) 
        : pimpl(std::move(p))
    {}

    server::server(server&&) noexcept = default;
    server& server::operator=(server&&) noexcept = default;
    server::~server() = default;

    result<server> server::create_named(std::wstring_view name)
    {
        auto impl = impl::create(name);
        if(!impl) return std::unexpected(impl.error());
        return server(std::move(*impl));
    }

    result<size_t> server::read(void* buf, size_t size)
    {
        return pimpl->read(buf, size, INFINITE);
    }

    result<size_t> server::read(void* buf, size_t size, uint32_t timeout_ms)
    {
        return pimpl->read(buf, size, timeout_ms);
    }

    result<size_t> server::write(std::string_view data)
    {
        return pimpl->write(data);
    }

    void server::close()
    {
        pimpl->close();
    }
}

namespace communications::pipe
{
    client::client(std::unique_ptr<impl> p) 
        : pimpl(std::move(p))
    {}

    client::client(client&&) noexcept = default;
    client& client::operator=(client&&) noexcept = default;
    client::~client() = default;

    //result<client> client::connect(std::wstring_view name, uint32_t timeout_ms)
    //{
    //    auto obj = impl::connect(name, timeout_ms);
    //    if(!obj)
    //        return std::unexpected(obj.error());

    //    return client(obj);
    //}
}