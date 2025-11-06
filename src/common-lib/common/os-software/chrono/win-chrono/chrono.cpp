#include "chrono.h"
#include "Windows.h"
#include <mutex>
#include <thread>

#include "Components/LogClass/LogFile.h"
#include "Components/StrCoding/ZStrCoding.h"


class win_api::chrono::registration::registration_data
{
public:
    static registration_data* get_singleton() noexcept;
    bool    get_certified(certified& result, CString& logText) noexcept;
    distance_result    get_distance(const certified& start, distance_type type, CString& logText) noexcept;
    bool free_certified(certified& cer, CString& logText) noexcept;

private:
    registration_data();
    ~registration_data();

private:
    container mAllCertified;
    LARGE_INTEGER mFrequency;
};


win_api::chrono::registration::registration_data::registration_data()
{
    auto result = ::QueryPerformanceFrequency(&mFrequency);
    ASSERT(TRUE == result);
    ASSERT(mFrequency.QuadPart != 0);
}

win_api::chrono::registration::registration_data::~registration_data()
{
    for(auto& iter : mAllCertified)
    {
        for(auto ele_iter : iter.second)
        {
            delete ele_iter;
        }
        iter.second.clear();
        delete iter.first;
    }
    mAllCertified.clear();
}

win_api::chrono::registration::registration_data* win_api::chrono::registration::registration_data::get_singleton() noexcept
{
    static registration_data singleton;
    return &singleton;
}

bool win_api::chrono::registration::registration_data::get_certified(certified& result, CString& logText) noexcept
{
    static std::mutex m;
    result = mAllCertified.cend();
    std::unique_ptr<LARGE_INTEGER> p;
    try
    {
        std::lock_guard<std::mutex> lm{ m };
        std::pair<LARGE_INTEGER*, std::list<LARGE_INTEGER*>> key_value;
        p = std::make_unique<LARGE_INTEGER>();
        if(::QueryPerformanceCounter(p.get()))
        {
            key_value.first = p.release();
            key_value.second = {};
            result = mAllCertified.insert(std::move(key_value)).first;
        }
        else
        {
            WLogText(logText, "断言失败：%u", ::GetLastError());
        }
    }
    catch(const std::exception& e)
    {
        p.reset();
        CStringA temp;
        WLogText_A(temp, "chrono 异常：%s", e.what());
        logText = ZStrCoding::AnsiToUnicode<CString>(temp.GetString());
        result = mAllCertified.cend();
    }
    return result != mAllCertified.cend();
}

win_api::chrono::registration::distance_result
win_api::chrono::registration::registration_data::get_distance(const certified& start, distance_type type, CString& logText) noexcept
{
    static std::mutex m;
    distance_result result;
    result.type = type;
    result.time = 0;
    result.count = 0;
    std::unique_ptr<LARGE_INTEGER> p;
    try
    {
        std::lock_guard<std::mutex> lm{ m };
        auto cIter = mAllCertified.find(start->first);
        do
        {
            if(cIter == mAllCertified.cend())
            {
                result.type = distance_type::kException;
                    WLogText(logText, "没有这个开始时间，当前共记录 %u 个时间", mAllCertified.size());
                break;
            }

            auto& list_ = cIter->second;
            p = std::make_unique<LARGE_INTEGER>();
            if(FALSE == ::QueryPerformanceCounter(p.get()))
            {
                result.type = distance_type::kException;
                    WLogText(logText, "断言失败：%u", ::GetLastError());
                break;
            }

            if(start->first->QuadPart > p->QuadPart)
            {
                result.type = distance_type::kException;
                    WLogText(logText, "异常：%lld %lld", start->first->QuadPart, p->QuadPart);
                break;
            }

            if(0 == mFrequency.QuadPart)
            {
                result.type = distance_type::kException;
                WLogText(logText, "异常：%lld", mFrequency.QuadPart);
                break;
            }

            result.time = (p->QuadPart - start->first->QuadPart) / (mFrequency.QuadPart / 1000000);
            switch(type)
            {
            case win_api::chrono::registration::distance_type::kUs:
                break;
            case win_api::chrono::registration::distance_type::kMs:
                result.time /= 1000;
                break;
            case win_api::chrono::registration::distance_type::kS:
                result.time /= 1000000;
                break;
            default:
                result.time = 0;
                p.reset();
                WLogText(logText, "错误类型：%u ", static_cast<std::uint8_t>(type));
                break;
            }

            if(p)
            {
                list_.push_back(p.release());
                result.count = list_.size();
            }

        } while(0);
    }
    catch(const std::exception& e)
    {
        p.reset();
        CStringA temp;
        WLogText_A(temp, "chrono 异常：%s", e.what());
        logText = ZStrCoding::AnsiToUnicode<CString>(temp.GetString());
        result.time = 0;
        result.type = distance_type::kException;
    }

    return result;
}

bool win_api::chrono::registration::registration_data::free_certified(certified& cer, CString& logText) noexcept
{
    bool result = false;
    try
    {
        const auto iter = mAllCertified.find(cer->first);
        if(iter != mAllCertified.cend())
        {
            for(auto ele : iter->second)
            {
                delete ele;
            }
            iter->second.clear();
            mAllCertified.erase(iter);
        }
        result = true;
    }
    catch(const std::exception& e)
    {
        CStringA temp;
        WLogText_A(temp, "chrono 异常：%s", e.what());
        logText = ZStrCoding::AnsiToUnicode<CString>(temp.GetString());
    }
    return result;
}


win_api::chrono::registration& win_api::chrono::registration::get_singleton() noexcept
{
    static registration singleton(win_api::chrono::registration::registration_data::get_singleton());
    return singleton;
}

bool win_api::chrono::registration::get_certified(certified& result, CString& logText) noexcept
{
    return mData ? mData->get_certified(result, logText) : false;
}

win_api::chrono::registration::distance_result 
win_api::chrono::registration::get_distance(const certified& start, distance_type type, CString& logText) noexcept
{
    return mData ? mData->get_distance(start, type, logText) : distance_result{};
}

bool win_api::chrono::registration::free_certified(certified& cer, CString& logText) noexcept
{
    return mData ? mData->free_certified(cer, logText) : false;
}

win_api::chrono::registration::registration(registration_data* p) :
    mData(p)
{}

win_api::chrono::registration::~registration()
{
    mData = nullptr;
}

