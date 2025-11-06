#pragma once
#define WIN32_LEAN_AND_MEAN // 从 Windows 头文件中排除极少使用的内容
#include <windows.h>
#include <memory>
#include <optional>
#include "common/string_define.h"

namespace windows
{
    class regedit
    {
    public:
        static regedit create(::HKEY root, const str::xview& subkey);
        static regedit open(::HKEY root, const str::xview& subkey);
        static regedit open(::HKEY root, const str::xview& subkey, bool allow_non_existent);

        std::optional<::DWORD> get_dword(const str::xview& name);
        std::optional<str::xtype> get_string(const str::xview& name);

        void set_dword(const str::xview& name, ::DWORD value);
        void set_string(const str::xview& name, const str::xview& value);

        void delete_value(const str::xview& name);

        bool is_exist()const;

        ~regedit();

    private:
        class impl;
        std::unique_ptr<impl> mImpl;
        explicit regedit(std::unique_ptr<impl>&& impl);
    };
}