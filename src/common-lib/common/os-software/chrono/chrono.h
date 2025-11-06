#pragma once
#include <cstdint>
#include <map>
#include <list>
#include "afxwin.h"

namespace win_api
{
    namespace chrono
    {
		class registration
		{
        private:
            class registration_data;

		public:
            using container = std::map<LARGE_INTEGER*, std::list<LARGE_INTEGER*>>;
            using certified = container::const_iterator;
            enum class distance_type : uint8_t
            {
                kUnknown = 0,
                kException,
                kUs,
                kMs,
                kS,
            };

            struct distance_result
            {
                std::uint64_t count{ 0 };
                std::uint64_t time{ 0 };
                distance_type type{ distance_type::kUnknown };
                operator bool()
                {
                    return count != 0 && type != distance_type::kUnknown;
                };
            };

            static registration& get_singleton() noexcept;
            bool    get_certified(certified& result, CString& logText) noexcept;
            distance_result    get_distance(const certified& start, distance_type type, CString& logText) noexcept;
            bool free_certified(certified& cer, CString& logText) noexcept;
		private:
			registration(registration_data* p);
			~registration();
            registration_data* mData;
		};
    }
}