/** -------------------------------------------------------------------------
 *  |                               _     _____    _____                    |
 *  |                       /\     | |   / ___/   / ___/                    |
 *  |                      /  \    | |  / /      / /                        |
 *  |                     / /\ \   | | ( (      ( (                         |
 *  |                    / / _\ \  | |  \ \___   \ \___                     |
 *  |                   /_/ /____\ |_|   \____/   \____/                    |
 *  |                                                                       |
 *  -------------------------------------------------------------------------
 *
 * @file configbase.h
 * @brief 配置基类
 * @details 读取配置文件，并解析
 * @author HuangTingxuan<huangtingxuan@china-aicc.cn>
 * @date 2023-07-05
 * Copyright 2023-2025 AICC Inc.
 *
 * These materials and the intellectual property rights associated therewith
 * (“Materials”) are proprietary to AICC Inc. Any and all rights in
 * the Materials are reserved by AICC Inc. Nothing contained in
 * these Materials shall grant or be deemed to grant to you or anyone else, by
 * implication, estoppel or otherwise, any rights in these Materials.
 *
 */
#ifndef LIC_COMMON_CONFIGBASE_H_
#define LIC_COMMON_CONFIGBASE_H_

#include "nlohmann/json.hpp"
#include "stdio.h"

using njson = nlohmann::json;

class ConfigBase {
   public:
    ConfigBase() {}
    ~ConfigBase() {}
    bool LoadFile(const std::string& file);
    std::string GetWorkDirect();
    int GetLogLevel() { return 1; }

   protected:
    njson json_;
};

#endif  // LIC_COMMON_CONFIGBASE_H_
