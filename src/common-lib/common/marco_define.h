#pragma once

#define DELETE_CLASS_FUNCTION(X) \
                                 X(const X&) = delete;\
                                 X& operator=(const X&) = delete;\
                                 X(X&&) = delete;\
                                 X& operator=(X&&) = delete