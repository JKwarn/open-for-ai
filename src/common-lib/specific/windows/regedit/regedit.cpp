#include "regedit.h"
#include <vector>
#include <memory>
#include "common/log/logger_help.h"
#include "common/encode/string/string-encode.h"


namespace windows
{
    class regedit::impl : public common::log::logger_help
    {
    private:
        ::HKEY mKeyHandle;

    public:
        impl(::HKEY root, const str::xview& subkey, bool create);
        ~impl();

        void set_dword(const str::xview& name, ::DWORD value);
        void set_string(const str::xview& name, const str::xview& value);

        std::optional<::DWORD> get_dword(const str::xview& name);
        std::optional<str::xtype> get_string(const str::xview& name);

        void delete_value(const str::xview& name);

        bool is_exist()const;

        enum class type_t : ::DWORD
        {
            kNONE = REG_NONE,
            kSZ = REG_SZ,
            kEXPAND_SZ = REG_EXPAND_SZ,
            kBINARY = REG_BINARY,
            kDWORD = REG_DWORD,
            kDWORD_LITTLE_ENDIAN = REG_DWORD_LITTLE_ENDIAN,
            kDWORD_BIG_ENDIAN = REG_DWORD_BIG_ENDIAN,
            kLINK = REG_LINK,
            kMULTI_SZ = REG_MULTI_SZ,
            kRESOURCE_LIST = REG_RESOURCE_LIST,
            kFULL_RESOURCE_DESCRIPTOR = REG_FULL_RESOURCE_DESCRIPTOR,
            kRESOURCE_REQUIREMENTS_LIST = REG_RESOURCE_REQUIREMENTS_LIST,
            kQWORD = REG_QWORD,	
            kQWORD_LITTLE_ENDIAN = REG_QWORD_LITTLE_ENDIAN,
        };

    private:
        bool validate_handle() const;
        static std::optional<str::xtype> get_error_message(::LSTATUS error_code);
        static constexpr std::uint16_t kMaxTpisLength{ 300 };

    public:
        using constructor_exception_code_t = std::uint16_t;
        static constexpr constructor_exception_code_t kConstructorExceptionCode{ 2 };
    };
}

namespace windows
{
    regedit::impl::impl(::HKEY root, const str::xview& subkey, bool create)
        : mKeyHandle(nullptr),
        logger_help("regedit")
    {
        ::LSTATUS result{0};
        if(create)
        {
            ::DWORD disposition{0};
            result = ::RegCreateKeyEx(root, subkey.data(), 0, nullptr,
                                      REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr,
                                      &mKeyHandle, &disposition);

            if(result != ERROR_SUCCESS)
            {
                auto tips = subkey.size() > kMaxTpisLength ? str::xtype(subkey.data(), kMaxTpisLength) : subkey.data();
                auto msg = WLogText("failed to create key {}.{}.{}:{}", static_cast<void*>(root), tips, subkey.size(), get_error_message(result).value());
                log_message(common::log::level_enum::info, msg);
                throw std::runtime_error(std::move(encode::string::utf16_to_utf8(msg)));
            }
        }
        else
        {
            result = ::RegOpenKeyEx(root, subkey.data(), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &mKeyHandle);
            if(result != ERROR_SUCCESS)
            {
                if(result == ERROR_FILE_NOT_FOUND)
                {
                    throw kConstructorExceptionCode;
                }
                else
                {
                    auto tips = subkey.size() > kMaxTpisLength ? str::xtype(subkey.data(), kMaxTpisLength) : subkey.data();
                    auto msg = WLogText("failed to open key {}.{}.{}:{}", static_cast<void*>(root), tips, subkey.size(), get_error_message(result).value());
                    log_message(common::log::level_enum::info, msg);
                    throw std::runtime_error(std::move(encode::string::utf16_to_utf8(msg)));
                }
            }
        }
    }
   
    regedit::impl::~impl()
    {
        if(mKeyHandle)
        {
            ::RegCloseKey(mKeyHandle);
            mKeyHandle = nullptr;
        }
    }

    std::optional<::DWORD> regedit::impl::get_dword(const str::xview& name)
    {
        do
        {
            ::DWORD type{ static_cast<::DWORD>(type_t::kDWORD) };
            ::DWORD value{0};
            ::DWORD size{sizeof(value)};
            const ::LSTATUS result = ::RegQueryValueEx(mKeyHandle, name.data(), nullptr, &type, reinterpret_cast<BYTE*>(&value), &size);
            if(result != ERROR_SUCCESS || type != REG_DWORD)
            {
                auto tips = name.size() > kMaxTpisLength ? str::xtype(name.data(), kMaxTpisLength) : name.data();
                log_message(common::log::level_enum::info,
                            WLogText("failed to get {}.{}.{}.{}:{}", 
                                     static_cast<void*>(mKeyHandle), tips, name.size(), type, get_error_message(result).value()));
                break;
            }

            return value;

        } while(0);

        return std::nullopt;
    }


    //void asd(const str::xtype& name)
    //{
    //    ::DWORD type = 0;
    //    ::DWORD size = 0;
    //    ::HKEY mKeyHandle;
    //    do
    //    {
    //        ::LSTATUS result = ::RegQueryValueEx(mKeyHandle, name.c_str(), nullptr, &type, nullptr, &size);
    //        if(result != ERROR_SUCCESS)
    //        {
    //            //log_message(common::log::level_enum::info,
    //            //            WLogText("failed to query string {}.{}:{}", static_cast<void*>(mKeyHandle), name, get_error_message(result).value()));
    //            break;
    //        }
    //    } while(0);
    //
    //}


    std::optional<str::xtype> regedit::impl::get_string(const str::xview& name)
    {
        do
        {
            ::DWORD type{ 0 };
            ::DWORD size{0};
            str::xtype tips;
            ::LSTATUS result = ::RegQueryValueEx(mKeyHandle, name.data(), nullptr, &type, nullptr, &size);
            if(result != ERROR_SUCCESS || type != REG_SZ)
            {
                tips = name.size() > kMaxTpisLength ? str::xtype(name.data(), kMaxTpisLength) : name.data();
                log_message(common::log::level_enum::info,
                            WLogText("failed to query string {}.{}.{}.{}:{}", 
                                     static_cast<void*>(mKeyHandle), tips, name.size(), type, get_error_message(result).value()));
                break;
            }

            constexpr auto factor = sizeof(str::xtype::value_type);
            std::unique_ptr<str::xtype::value_type[]> p = std::make_unique<str::xtype::value_type[]>(size / factor);
            result = ::RegQueryValueEx(mKeyHandle, name.data(), nullptr, &type, reinterpret_cast<BYTE*>(p.get()), &size);
            if(result != ERROR_SUCCESS)
            {
                tips = name.size() > kMaxTpisLength ? str::xtype(name.data(), kMaxTpisLength) : name.data();
                log_message(common::log::level_enum::info,
                WLogText("failed to get string {}.{}.{}.{}:{}",
                         static_cast<void*>(mKeyHandle), tips, name.size(), type, get_error_message(result).value()));
                break;
            }

            str::xtype value;
            if(p)
            {
                str::xview view(p.get(), size / factor);
                while(view.back() == TEXT('\0'))
                {
                    view.remove_suffix(1);
                }

                value = view;
            }
            return value;

        } while(0);

        return std::nullopt;
    }

    void regedit::impl::set_dword(const str::xview& name, ::DWORD value)
    {
        const LSTATUS result = ::RegSetValueEx(mKeyHandle, name.data(), 0, REG_DWORD,
                                               reinterpret_cast<const BYTE*>(&value), sizeof(decltype(value)));
        if(result != ERROR_SUCCESS)
        {
            auto tips = name.size() > kMaxTpisLength ? str::xtype(name.data(), kMaxTpisLength) : name.data();
            log_message(common::log::level_enum::info,
                        WLogText("failed to set dword {}.{}.{}.{}:{}", 
                                 static_cast<void*>(mKeyHandle), tips, name.size(), value, get_error_message(result).value()));
        }
    }

    void regedit::impl::set_string(const str::xview& name, const str::xview& value)
    {
        const LSTATUS result = ::RegSetValueEx(mKeyHandle, name.data(), 0, REG_SZ,
                                               reinterpret_cast<const BYTE*>(value.data()),
                                               static_cast<::DWORD>(value.size() + 1));

        if(result != ERROR_SUCCESS)
        {
            auto tips = name.size() > kMaxTpisLength ? str::xtype(name.data(), kMaxTpisLength) : name.data();
            log_message(common::log::level_enum::info,
                        WLogText("failed to set string {}.{}.{}.{}:{}", 
                                 static_cast<void*>(mKeyHandle), tips, name.size(), value, get_error_message(result).value()));
        }
    }

    void regedit::impl::delete_value(const str::xview& name)
    {
        const LSTATUS result = ::RegDeleteValue(mKeyHandle, name.data());
        if(result != ERROR_SUCCESS)
        {
            auto tips = name.size() > kMaxTpisLength ? str::xtype(name.data(), kMaxTpisLength) : name.data();
            log_message(common::log::level_enum::info,
                        WLogText("failed to delete {}.{}.{} value:{}", 
                                 static_cast<void*>(mKeyHandle), tips, name.size(), get_error_message(result).value()));
        }
    }

    bool regedit::impl::is_exist() const
    {
        return validate_handle();
    }

    bool regedit::impl::validate_handle() const
    {
        return mKeyHandle != nullptr;
    }

    std::optional<str::xtype> regedit::impl::get_error_message(::LSTATUS error_code)
    {
        TCHAR* buff = nullptr;
        const ::DWORD size = ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                             nullptr, error_code, 0, reinterpret_cast<TCHAR*>(&buff), 0, nullptr);
        const ::DWORD er = ::GetLastError();
        str::xtype message;
        do
        {
            if(0 == size)
            {
                message = WLogText("format err:{}", er);
                break;
            }

            message.reserve(size);
            message = buff;
            ::LocalFree(buff);

            while(!message.empty() &&
                  (message.back() == '\n' || message.back() == '\r'))
            {
                message.pop_back();
            }

        } while(0);

        return std::optional<str::xtype>(std::move(message));
    }
}

namespace windows
{
    regedit::regedit(std::unique_ptr<impl>&& impl) : mImpl(std::move(impl))
    {}
    regedit::~regedit() = default;

    regedit regedit::create(::HKEY root, const str::xview& subkey)
    {
        return regedit(std::make_unique<impl>(root, subkey, true));
    }

    regedit regedit::open(::HKEY root, const str::xview& subkey)
    {
        return regedit(std::make_unique<impl>(root, subkey, false));
    }

    regedit regedit::open(::HKEY root, const str::xview& subkey, bool allow_non_existent)
    {
        try
        {
            return regedit(std::make_unique<impl>(root, subkey, false));
        }
        catch(impl::constructor_exception_code_t exception)
        {
            if(exception == impl::kConstructorExceptionCode && allow_non_existent)
            {
                return regedit(nullptr);
            }
            else
            {
                std::rethrow_exception(std::current_exception());
            }
        }
        catch(...)
        {
            std::rethrow_exception(std::current_exception());
        }
    }

    std::optional<::DWORD> regedit::get_dword(const str::xview& name)
    {
        return mImpl->get_dword(name);
    }

    std::optional<str::xtype> regedit::get_string(const str::xview& name)
    {
        return mImpl->get_string(name);
    }

    void regedit::set_dword(const str::xview& name, ::DWORD value)
    {
        mImpl->set_dword(name, value);
    }

    void regedit::set_string(const str::xview& name, const str::xview& value)
    {
        mImpl->set_string(name, value);
    }

    void regedit::delete_value(const str::xview& name)
    {
        mImpl->delete_value(name);
    }

    bool regedit::is_exist() const
    {
        return mImpl ? mImpl->is_exist() : false;
    }

}