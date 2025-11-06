#pragma once
#ifndef _COMMON_JSON_H_
#define _COMMON_JSON_H_

#include "05-3rd/include/nlohmann/json.h"

#include <fstream>
#include <expected>
#include <string>
#include "common/fmt/fmt-pch.h"

namespace common::json
{
    using obj_type = nlohmann::json; // 友好提示
    using call_ret = std::expected<bool, std::string>;
    template<typename T>
    call_ret write_config_to_file(const std::string& file_path, T& obj)
    {
        try
        {
            nlohmann::json json_obj = obj;
            std::ofstream fstream(file_path, std::ios_base::trunc | std::ios_base::out);
            if(false == fstream.is_open())
            {
                return std::unexpect(xfmt::format("{} failed to open file:{} ", __LINE__, file_path));
            }

            fstream << json_obj.dump(4) << '\n';  // 使用\n避免自动flush
            if(!fstream)
            {
                return std::unexpect(xfmt::format("{}:{} failed to write {} ", __LINE__, ::GetLastError(), file_path));
            }
            fstream.close();
        }
        catch(const std::exception& exception)
        {
            return std::unexpect(xfmt::format("{} failed to write {} exception {} ", __LINE__, file_path, exception.what()));
        }

        return true;
    }

    template<typename T>
    call_ret read_config_from_file(const std::string& file_path, T& out_obj)
    {
        try
        {
            std::ifstream fstream(file_path, std::ios::in);
            if(false == fstream.is_open())
            {
                return std::unexpect(xfmt::format("{} failed to open file:{} ", __LINE__, file_path));
            }

            nlohmann::json json_obj;
            fstream >> json_obj;
            out_obj = json_obj.get<T>();  // 自动使用移动语义
            fstream.close();
        }
        catch(const std::exception& exception)
        {
            return std::unexpect(xfmt::format("{} failed to read {} exception {} ", __LINE__, file_path, exception.what()));
        }

        return true;
    }
}
#endif