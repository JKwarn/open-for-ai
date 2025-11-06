#pragma once
#ifndef _TYPE_DEFINE_H_
#define _TYPE_DEFINE_H_


// 平台检测宏
#if defined(_WIN32)
#define CPP_WINDOWS 1
#define CPP_LINUX   0
#elif defined(__linux__)
#define CPP_WINDOWS 0
#define CPP_LINUX   1
#else
#error "Unsupported platform"
#endif

// 标准头文件包含
#include <cstdint>
#include <type_traits>

// 平台特定头文件
#if CPP_WINDOWS
#include <windows.h>
#elif CPP_LINUX
#include <unistd.h>     // 用于pid_t等
#include <sys/types.h>  // 用于基本系统类型
#endif

// 平台兼容类型定义
namespace common 
{
    // 基础类型
    using dword = std::uint32_t;
#if CPP_WINDOWS
    static_assert(
        (std::is_integral_v<dword>&& std::is_integral_v<::DWORD>)
        && (sizeof(dword) == sizeof(::DWORD)), "dword not same");
    using handle = ::HANDLE;
    //using BOOL = ::BOOL;
    //using LPVOID = ::LPVOID;
#else
    using handle = void*;      // 或根据实际需求定义为int
    //using BOOL = std::int32_t;
    //using LPVOID = void*;
#endif

    //// 跨平台统一类型定义
    //using uint = unsigned int;
    //using ulong = unsigned long;
    //using intptr = intptr_t;
    //using uintptr = uintptr_t;

    // 特殊句柄定义
#if CPP_LINUX
    using FileHandle = int;              // 文件描述符
    using SocketHandle = int;            // Socket描述符
    constexpr handle INVALID_HANDLE = reinterpret_cast<handle>(-1);
#else
    using FileHandle = handle;           // Windows文件句柄
    using SocketHandle = SOCKET;         // Windows Socket类型
    constexpr handle INVALID_HANDLE = INVALID_HANDLE_VALUE;
#endif

    // 函数调用约定
#if CPP_WINDOWS
#define CP_API __stdcall
#define CP_CDECL __cdecl
#else
#define CP_API 
#define CP_CDECL 
#endif

// 错误码处理
#if CPP_WINDOWS
#define CP_GET_LAST_ERROR() ::GetLastError()
#else
#define CP_GET_LAST_ERROR() errno
#endif

// 线程相关类型
#if CPP_WINDOWS
    using ThreadHandle = handle;
    using ThreadId = dword;
#else
    using ThreadHandle = pthread_t;
    using ThreadId = pid_t;
#endif

} // namespace cp_types

// 常用宏定义
#if CPP_WINDOWS
#define CP_INLINE __inline
#define CP_FORCEINLINE __forceinline
#else
#define CP_INLINE inline __attribute__((always_inline))
#define CP_FORCEINLINE __attribute__((always_inline)) inline
#endif

// 导出符号修饰
#if CPP_WINDOWS
#define CP_EXPORT __declspec(dllexport)
#define CP_IMPORT __declspec(dllimport)
#else
#define CP_EXPORT __attribute__((visibility("default")))
#define CP_IMPORT
#endif


#endif