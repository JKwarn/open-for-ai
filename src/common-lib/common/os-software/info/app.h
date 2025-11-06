#pragma once
#ifndef _COMMON_OS_SOFTWARE_INFO_APP_H_
#define _COMMON_OS_SOFTWARE_INFO_APP_H_

#include <string>
#include <type_traits>
#include <functional>

#include "common/string_define.h"
#include "common/marco_define.h"
#include "common/encode/string/string-encode.h"

//namespace auto_to
//{
//
//    template<typename type>
//    class auto_to
//    {
//    public:
//        constexpr app()
//        {
//            static_assert(get::kNumber > static_cast<int>(type), "not support that get method");
//        };
//        ~app() = default;
//
//        template<typename T>
//        operator T()&&
//        {
//            static_assert(std::is_convertible_v<std::string, T> || std::is_convertible_v<std::wstring, T>, "not support that convert");
//            std::function<std::wstring()> func;
//            switch(type)
//            {
//            case os::software::info::kPath:
//                func = &app::get_app_path_impl;
//                break;
//            case os::software::info::kDirPath:
//                func = &app::get_app_dir_path_impl;
//                break;
//            case os::software::info::kFileVersion:
//                func = &app::get_app_file_version_impl;
//                break;
//            case os::software::info::kProductVersion:
//                func = &app::get_app_product_version_impl;
//                break;
//            default:
//                *(int*)(nullptr) = 1;
//                break;
//            }
//
//            if constexpr(std::is_convertible_v<T, std::wstring>)
//            {
//                return func();
//            }
//            else
//            {
//                return encode::string::utf16_to_utf8(func());
//            }
//        }
//
//
//}




namespace os::software::info
{
    enum get
    {
        kPath,
        kDirPath,
        kFileVersion,
        kProductVersion,
        kNumber,
    };

    template<get type>
    class app
    {
    public:
        constexpr app()
        {
            static_assert(get::kNumber > static_cast<int>(type), "not support that get method");
        };
        ~app() = default;

        template<typename T>
        operator T()&&
        {
            static_assert(std::is_convertible_v<std::string, T> || std::is_convertible_v<std::wstring, T>, "not support that convert");
            std::function<std::wstring()> func;
            switch(type)
            {
            case os::software::info::kPath:
                func = &app::get_app_path_impl;
                break;
            case os::software::info::kDirPath:
                func = &app::get_app_dir_path_impl;
                break;
            case os::software::info::kFileVersion:
                func = &app::get_app_file_version_impl;
                break;
            case os::software::info::kProductVersion:
                func = &app::get_app_product_version_impl;
                break;
            default:
                *(int*)(nullptr) = 1;
                break;
            }

            if constexpr(std::is_convertible_v<T, std::wstring>)
            {
                return func();
            }
            else
            {
                return encode::string::utf16_to_utf8(func());
            }
        }

    private:
        static std::wstring get_app_path_impl();
        static std::wstring get_app_dir_path_impl();
        static std::wstring get_app_file_version_impl();
        static std::wstring get_app_product_version_impl();
    };

}

#endif