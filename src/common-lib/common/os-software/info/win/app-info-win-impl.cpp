#pragma once
#ifndef _COMMON_OS_SOFTWARE_INFO_APP_WIN_IMPL_H_
#define _COMMON_OS_SOFTWARE_INFO_APP_WIN_IMPL_H_

#pragma comment(lib, "Version.lib") // Api-ms-win-core-version-l1-1-0.dll

#include <Windows.h>
#include <string>
#include "src/encode/string/string-encode.h"
#include "src/fmt/fmt-pch.h"
#include "src/string_define.h"
#include "src/log/log.h"
#include "../app.h"


// 用于日志记录
template<typename T>
    requires (std::is_convertible_v<T, std::string> || std::is_convertible_v<T, std::wstring>)
static void log_message(int level, const T& message)
{
    static common::log::logger_ptr log{ common::log::manager::instance().create_log_file("info") };
    if(log)
    {
        log->write_log(level, message);
    }
}


namespace os::software::info
{
    struct version_info_t
    {
        std::wstring file_version;
        std::wstring product_version;
    };

    version_info_t get_module_version(const str::xtype& module_path)
    {
        version_info_t result;
        do
        {
            ::DWORD info_size = ::GetFileVersionInfoSize(module_path.c_str(), 0);
            if(0 == info_size)
            {
                log_message(common::log::level_enum::err, WLogText("{}.{} failed to get", module_path, ::GetLastError()));
                break;
            }

            std::uint8_t* pBuff = new std::uint8_t[info_size + 1]{ 0 };
            do
            {
                if(FALSE == ::GetFileVersionInfo(module_path.c_str(), 0, info_size, pBuff))
                {
                    log_message(common::log::level_enum::err, WLogText("{}.{} failed to get", module_path, ::GetLastError()));
                    break;
                }

                std::uint32_t size = 0;
                ::VS_FIXEDFILEINFO* tempObj = nullptr;
                if(FALSE == ::VerQueryValue(pBuff, TEXT("\\"), (LPVOID*)&tempObj, &size))
                {
                    log_message(common::log::level_enum::err, WLogText("{}.{} failed to get", module_path, ::GetLastError()));
                    break;
                }

                struct LANGANDCODEPAGE
                {
                    WORD wLanguage;
                    WORD wCodePage;
                };

                // Read the list of languages and code pages.
                LANGANDCODEPAGE* pTranslate = nullptr;
                if(FALSE == ::VerQueryValue(pBuff, TEXT(R"(\VarFileInfo\Translation)"), (LPVOID*)&pTranslate, &size))
                {
                    log_message(common::log::level_enum::err, WLogText("{}.{} failed to get", module_path, ::GetLastError()));
                    break;
                }

                auto file_version = xfmt::format(TEXT(R"(\StringFileInfo\{:0>4x}{:0>4x}\FileVersion)"), pTranslate->wLanguage, pTranslate->wCodePage);
                auto product_version = xfmt::format(TEXT(R"(\StringFileInfo\{:0>4x}{:0>4x}\ProductVersion)"), pTranslate->wLanguage, pTranslate->wCodePage);

                void* lpBuffer = nullptr;
                if(TRUE == ::VerQueryValue(pBuff, file_version.c_str(), &lpBuffer, &size) && lpBuffer)
                {
                    result.file_version = (WCHAR*)lpBuffer;
                }

                if(TRUE == ::VerQueryValue(pBuff, product_version.c_str(), &lpBuffer, &size) && lpBuffer)
                {
                    result.product_version = (WCHAR*)lpBuffer;
                }

                auto func = [](std::wstring& container)
                    {
                        for(auto& ele : container)
                        {
                            if(ele == TEXT(','))
                            {
                                ele = TEXT('.');
                            }

                            if(ele == TEXT(' '))
                            {
                                ele = TEXT('0');
                            }
                        }
                    };

                func(result.file_version);
                func(result.product_version);

            } while(0);

            delete[] pBuff;
            pBuff = nullptr;

        } while(0);

        return result;
    }

    //std::string os::software::info::get_app_path()
    //{
    //    return encode::string::utf16_to_utf8(get_app_path_impl());
    //}


    template<get type>
    std::wstring os::software::info::app<type>::get_app_path_impl()
    {
        constexpr size_t len = 4096;
        std::wstring app_path;
        do
        {
            wchar_t path[len]{ 0 };
            auto getResult = ::GetModuleFileNameW(NULL, path, len - 1);
            if(getResult == 0)
            {
                app_path = TEXT("");
                log_message(common::log::level_enum::err, WLogText("{} failed to get", ::GetLastError()));
                break;
            }

            app_path = path;
            if(getResult == (len - 1))
            {
                log_message(common::log::level_enum::err, WLogText("{} {} {} failed to get", app_path, len - 1, ::GetLastError()));
                app_path = TEXT("");
                break;
            }

            for(auto& ele : app_path)
            {
                if(ele == '\\')
                {
                    ele = '/';
                }
            }

        } while(0);

        return app_path;
    }


    //std::string os::software::info::get_app_dir_path()
    //{
    //    return encode::string::utf16_to_utf8(get_app_dir_path_impl());
    //}
    template<get type>
    std::wstring os::software::info::app<type>::get_app_dir_path_impl()
    {
        std::wstring app_dir_path = get_app_path_impl();
        if(app_dir_path.empty())
        {
            return TEXT("");
        }

        auto pos = app_dir_path.find_last_of('/');
        if(pos != std::wstring::npos && pos + 1 < app_dir_path.size())
        {
            app_dir_path.resize(pos + 1);
        }

        return app_dir_path;
    }

    template<get type>
    std::wstring app<type>::get_app_file_version_impl()
    {
        auto result = os::software::info::get_module_version(os::software::info::app<type>::get_app_path_impl());
        return result.file_version;
    }

    template<get type>
    std::wstring app<type>::get_app_product_version_impl()
    {
        auto result = os::software::info::get_module_version(os::software::info::app<type>::get_app_path_impl());
        return result.product_version;
    }

}
#endif