#pragma once
#ifndef _STRING_SWITCH_H_
#define _STRING_SWITCH_H_

#include <string>

namespace str
{

#ifdef _UNICODE
using xtype = std::wstring;
using xview = std::wstring_view;
#define TO_TEXT(quote)  L##quote 


#endif // _UNICODE






#ifndef _UNICODE
using xtype = std::string;
using xview = std::string_view;
#define TO_TEXT(quote)  quote 




#endif // _UNICODE

}


#endif // !_STRING_SWITCH_H_
