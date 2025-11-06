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
#include <optional>
std::optional<int>;

// 平台特定头文件
#if CP_WINDOWS
#include <windows.h>
#elif CP_LINUX
#include <unistd.h>     // 用于pid_t等
#include <sys/types.h>  // 用于基本系统类型
#endif

// 平台兼容类型定义
namespace common 
{
    // 基础类型
#if CP_WINDOWS
    using DWORD = ::DWORD;
    using HANDLE = ::HANDLE;
    using BOOL = ::BOOL;
    using LPVOID = ::LPVOID;
#else
    using DWORD = std::uint32_t;
    using HANDLE = void*;      // 或根据实际需求定义为int
    using BOOL = std::int32_t;
    using LPVOID = void*;
#endif

    //// 跨平台统一类型定义
    //using uint = unsigned int;
    //using ulong = unsigned long;
    //using intptr = intptr_t;
    //using uintptr = uintptr_t;

    // 特殊句柄定义
#if CP_LINUX
    using FileHandle = int;              // 文件描述符
    using SocketHandle = int;            // Socket描述符
    constexpr HANDLE INVALID_HANDLE = reinterpret_cast<HANDLE>(-1);
#else
    using FileHandle = HANDLE;           // Windows文件句柄
    using SocketHandle = SOCKET;         // Windows Socket类型
    constexpr HANDLE INVALID_HANDLE = INVALID_HANDLE_VALUE;

    struct file_fd : public std::optional<HANDLE>
    {
        ;
    };
#endif

    // 函数调用约定
#if CP_WINDOWS
#define CP_API __stdcall
#define CP_CDECL __cdecl
#else
#define CP_API 
#define CP_CDECL 
#endif

// 错误码处理
#if CP_WINDOWS
#define CP_GET_LAST_ERROR() ::GetLastError()
#else
#define CP_GET_LAST_ERROR() errno
#endif

// 线程相关类型
#if CP_WINDOWS
    using ThreadHandle = HANDLE;
    using ThreadId = DWORD;
#else
    using ThreadHandle = pthread_t;
    using ThreadId = pid_t;
#endif

} // namespace cp_types

// 常用宏定义
#if CP_WINDOWS
#define CP_INLINE __inline
#define CP_FORCEINLINE __forceinline
#else
#define CP_INLINE inline __attribute__((always_inline))
#define CP_FORCEINLINE __attribute__((always_inline)) inline
#endif

// 导出符号修饰
#if CP_WINDOWS
#define CP_EXPORT __declspec(dllexport)
#define CP_IMPORT __declspec(dllimport)
#else
#define CP_EXPORT __attribute__((visibility("default")))
#define CP_IMPORT
#endif


#endif