#include "./app.h"


#if WIN32
#include "./win/app-info-impl.cpp"
#endif // _WIN32

template os::software::info::app<os::software::info::get::kPath>;
template os::software::info::app<os::software::info::get::kDirPath>;
template os::software::info::app<os::software::info::get::kFileVersion>;
template os::software::info::app<os::software::info::get::kProductVersion>;