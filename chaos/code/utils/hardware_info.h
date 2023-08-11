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
 * @file hardware_info.h
 * @brief 获取硬件信息
 * @details 通过系统接口获取硬件信息
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
#ifndef LIC_COMMON_HARDWARE_INFO_H_
#define LIC_COMMON_HARDWARE_INFO_H_

#include <iostream>

namespace utils {

std::string GetHardWareInfo();

}

#endif  // LIC_COMMON_HARDWARE_INFO_H_
