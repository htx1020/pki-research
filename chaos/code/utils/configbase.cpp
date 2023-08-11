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
 * @file configbase.cpp
 * @brief 配置解析基类
 * @details 解析配置文件
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
#include "configbase.h"

#include <stdio.h>

#include <fstream>
#include <iostream>

bool ConfigBase::LoadFile(const std::string &file)
{
    std::ifstream ifile(file);
    if (!ifile.is_open())
    {
        std::cerr << "打开文件失败\n";
        return false;
    }
    try
    {
        ifile >> this->json_;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception Caught: " << e.what() << std::endl;
        return false;
    }

    return true;
}

std::string ConfigBase::GetWorkDirect()
{
    if (!json_["work_path"].is_null())
    {
        return json_["work_path"];
    };
    return "/tmp/";
}
