/** -------------------------------------------------------------------------
 *  |                               _     _____    _____                    |
 *  |                       /\     | |   / ___/   / ___/                    |
 *  |                      /  \    | |  / /      / /                        |
 *  |                     / /\ \   | | < <      / /                        |
 *  |                    / / _\ \  | |  \ \___   \ \___                     |
 *  |                   /_/ /____\ |_|   \____/   \____/                    |
 *  |                                                                       |
 *  -------------------------------------------------------------------------
 *
 * @file store.h
 * @brief 存储信息
 * @details 存储信息的索引信息
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
#ifndef LIC_COMMON_STORE_H_
#define LIC_COMMON_STORE_H_

namespace store {
enum
{
    kFlagReadDisable = 0,
    kFlagReadEnable  = 1,
};

enum
{
    kIdOfServerPrikey  = 0x1001,
    kIdOfServerPubkey  = 0x1002,
    kIdOfServerCert    = 0x1003,
    kIdOfClientLicense = 0x1004,
    kIdOfRunTimeLine   = 0x100F,
};
} // namespace store

#endif // LIC_COMMON_STORE_H_
