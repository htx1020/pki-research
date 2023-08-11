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
 * @file garbo.h
 * @brief 资源回收
 * @details
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
#ifndef LIC_COMMON_GARBO_H
#define LIC_COMMON_GARBO_H

/* 垃圾工类用于释放单实例申请的内存;
   NOTICE:实例化模板类型必须有getInstance成员函数，否则模板展开会异常 */

template <typename T>
class CGarbo {
   public:
    ~CGarbo() {
        if (nullptr != T::getInstance()) {
            delete T::getInstance();
        }
    }
};

#endif /* GARBO_H */
