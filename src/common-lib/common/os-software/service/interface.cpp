#pragma once
#ifndef _XIXI_HOST_SERVICE_H_
#define _XIXI_HOST_SERVICE_H_

#include "./interface.h"


#ifdef WIN32
#include "pch.h"
#include "./win/service-impl.cpp"
#endif // _WIN32

#endif