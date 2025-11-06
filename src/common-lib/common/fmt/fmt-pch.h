#pragma once
#ifndef _FMT_PCH_H_
#define _FMT_PCH_H_

#ifdef _MSVC_LANG
#  define FMT_CPLUSPLUS _MSVC_LANG
#else
#  define FMT_CPLUSPLUS __cplusplus
#endif

#  if FMT_CPLUSPLUS > 202002L
// 如果可以使用标准库
#    include <format>
namespace xfmt = std;

#  else
#    include "./fmt-11-1-1/include/fmt/core.h"
#    include "./fmt-11-1-1/include/fmt/args.h"
#    include "./fmt-11-1-1/include/fmt/base.h"
#    include "./fmt-11-1-1/include/fmt/chrono.h"
#    include "./fmt-11-1-1/include/fmt/color.h"
#    include "./fmt-11-1-1/include/fmt/compile.h"
#    include "./fmt-11-1-1/include/fmt/format.h"
#    include "./fmt-11-1-1/include/fmt/format-inl.h"
#    include "./fmt-11-1-1/include/fmt/os.h"
#    include "./fmt-11-1-1/include/fmt/ostream.h"
#    include "./fmt-11-1-1/include/fmt/printf.h"
#    include "./fmt-11-1-1/include/fmt/ranges.h"
#    include "./fmt-11-1-1/include/fmt/std.h"
#    include "./fmt-11-1-1/include/fmt/xchar.h"
namespace xfmt = fmt;
#  endif


#endif