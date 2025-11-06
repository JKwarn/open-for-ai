#pragma once
#ifndef _COMMON_STRING_ENCODE_H_
#define _COMMON_STRING_ENCODE_H_

#include <string>
#include <type_traits>
namespace encode
{
    namespace string
    {
        template<typename T, typename old_type, typename new_type>
        T convert_to_new_encode(const old_type* pOldStr, int newEncodeCodePage);

        template<typename T = std::wstring>
        T utf8_to_utf16(const char* pOldStr);

        template<typename T = std::string>
        T utf16_to_utf8(const wchar_t* pOldStr);

        template<typename T = std::wstring>
        T utf8_to_utf16(const std::string& old_string);

        template<typename T = std::string>
        T utf16_to_utf8(const std::wstring& old_string);
    }
}

//
//typedef std::vector<CString> CStringVect;
//class ZStrCoding
//{
//public:
//    ZStrCoding(void);
//    ~ZStrCoding(void);
//public:
//    static CString GetUrlCode(CString strSrc);
//    static std::string ToHalf(std::string str);//全角转半角
//    static std::string ToFull(std::string str);//半角转全角
//public:
//    static void UTF_8ToGB2312(std::string& pOut, char* pText, int pLen);//utf_8转为gb2312
//    static void GB2312ToUTF_8(std::string& pOut, char* pText, int pLen); //gb2312 转utf_8
//    static std::string UrlGB2312(char* str);                         //urlgb2312编码
//    static std::string UrlUTF8(char* str);                             //urlutf8 编码
//    static std::string UrlUTF8Decode(std::string str);                //urlutf8解码
//    static std::string UrlGB2312Decode(std::string str);           //urlgb2312解码
//
//    static void Gb2312ToUnicode(WCHAR* pOut, char* gbBuffer);
//    static void UTF_8ToUnicode(WCHAR* pOut, char* pText);
//    static void UnicodeToUTF_8(char* pOut, WCHAR* pText);
//    static void UnicodeToGB2312(char* pOut, WCHAR uData);
//    static char CharToInt(char ch);
//    static char StrToBin(char* str);
//
//    static wstring Utf8ToUnicode(const std::string& strSrc);
//    static wstring Utf8ToUnicodeEx(char* pBuf);
//
//    static std::string Utf8ToAnsi(const std::string& strUtf8);
//    static std::string Utf8ToAnsi(char* pUtf8);
//    static std::string Utf8ToAnsiEx(char* pBuf);
//
//    template<typename T>
//    static T AnsiToUnicode(const char* pStrAnsi);
//    template<typename T>
//    static T UnicodeToAnsi(const wchar_t* pStrUnicode);
//    template<typename T = std::string>
//    static T UnicodeToUTF8(const wchar_t* pStrUnicode);
//
//public:
//    static CString JsonToCmdLineJson(CString strJson);
//    static BOOL GetJsonObjFromCmdLine(OUT Json::Value& vRoot);
//
//    static CString LongToStr(INT64 nNum);//数字转为字符串
//
//    //将strSrc 中 strOldChars 列出的字符替换为 strNewChar
//    static CString ReplaceChars(CString strSrc, CString strOldChars, CString strNewChar);
//    /*
//    分割字符串
//    strSrc：待分割字符串
//    strPattern：分割符
//    */
//    static CStringVect StrSplit(CString strSrc, CString strPattern);
//
//    static std::string Encrypt(std::string strSrc);//加密
//    static std::string Deciphering(std::string strSrc);//解密
//
//    static std::string EncryptWithKey(std::string strSrc, std::string strKey);//加密
//
//    static void FirstLetter(int nCode, OUT char& strLetter);
//    static void GetFirstLetter(char* strName, char* strFirstLetter, int nLen);
//    static BOOL IsChinese(INT16 wdCh);
//
//
//    static std::string byteToHexStr(unsigned char byte_arr[], int arr_len);
//    static wstring s2ws(const std::string& s);
//
//    static std::string GetUTF8HMAC_SHA1(CString sha1text);  //整理下，HMAC_SHA1 加密前的字符串
//
//};



#include <windows.h>
extern int WINAPI
m_to_w(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar,
    LPCCH,
    LPBOOL
);


extern int WINAPI
w_to_m(
    UINT CodePage,
    DWORD dwFlags,
    LPCWCH lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCCH lpDefaultChar,
    LPBOOL lpUsedDefaultChar
);


template<typename T, typename old_type, typename new_type>
T encode::string::convert_to_new_encode(const old_type* pOldStr, int newEncodeCodePage)
{
    static_assert(!std::is_same_v<old_type, new_type>, " must different");
    static_assert(std::is_same_v<old_type, char> || std::is_same_v<old_type, wchar_t>, " char or wchar");
    static_assert(std::is_same_v<new_type, char> || std::is_same_v<new_type, wchar_t>, " char or wchar");

    int len = 0;
    using type = std::conditional_t<std::is_same_v<old_type, char>, decltype(::m_to_w), decltype(::w_to_m)>;
    void* func = nullptr;
    if(std::is_same_v<old_type, char>)
    {
        func = &::m_to_w;
    }
    else
    {
        func = &::w_to_m;
    }

    new_type* pBuff = nullptr;
    do
    {
        int len = ((type*)func)(newEncodeCodePage, 0, pOldStr, -1, NULL, 0, NULL, NULL);
        if(len == 0)
        {
            break;
        }
        pBuff = new new_type[len + 1];
        pBuff[len] = 0;
        ((type*)func)(newEncodeCodePage, 0, pOldStr, -1, pBuff, len, NULL, NULL);

    } while(0);

    if(pBuff)
    {
        T obj{ pBuff };
        delete[] pBuff;
        return obj;
    }
    else
    {
        //return T{ std::to_wstring(::GetLastError()).c_str() };
        return T{};
    }
}

template<typename T>
T encode::string::utf8_to_utf16(const char* pOldStr)
{
    return convert_to_new_encode<T, char, wchar_t>(pOldStr, CP_UTF8);
}

template<typename T>
T encode::string::utf16_to_utf8(const wchar_t* pOldStr)
{
    return convert_to_new_encode<T, wchar_t, char>(pOldStr, CP_UTF8);
}

template<typename T>
T encode::string::utf8_to_utf16(const std::string& old_string)
{
    return utf8_to_utf16(old_string.c_str());
}

template<typename T>
T encode::string::utf16_to_utf8(const std::wstring& old_string)
{
    return utf16_to_utf8(old_string.c_str());
}

#endif // !_STRING_ENCODE_H_