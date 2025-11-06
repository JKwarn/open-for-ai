#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <windows.h>

int
WINAPI
m_to_w(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar,
    LPCCH,
    LPBOOL
)
{
    return ::MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
};

int
WINAPI
w_to_m(
    UINT CodePage,
    DWORD dwFlags,
    LPCWCH lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCCH lpDefaultChar,
    LPBOOL lpUsedDefaultChar
)
{
    return ::WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
};
