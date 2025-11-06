#pragma once
#include<string>

#ifdef _MSVC_LANG
#  define CPP_VERSION_ _MSVC_LANG
#else
#  define CPP_VERSION_ __cplusplus
#endif

namespace common::result
{
    using error_text_t = ::std::string;


#if (CPP_VERSION_ > 202002L)
#include<expected>
    namespace xstd = ::std; // x-expected not xexpected

#else
#endif

    template <typename T>
    using result = xstd::expected<T, error_text_t>;
    using void_result = result<void>;
    using bool_result = result<bool>;
    using str_resutl = result<error_text_t>;
    using uint32_resutl = result<::std::uint32_t>;
}