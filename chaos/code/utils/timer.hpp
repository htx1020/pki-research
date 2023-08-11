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
 * @file timer.hpp
 * @brief 定时器
 * @details 常用的定时器
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
#ifndef LIC_COMMON_TIMER_H_
#define LIC_COMMON_TIMER_H_

#include "utils.h"
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>

///< 不具名空间
namespace {
template <typename T>
inline T Abs(T val)
{
    return val > 0 ? val : -val;
}

inline uint64_t GetMilliSec()
{
    // 获取当前时间点
    auto now = std::chrono::high_resolution_clock::now();

    // 转换为时间戳(微秒)
    auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    return timestamp;
}
} // namespace

class Timer {
public:
    Timer(const std::string name = "") : running_(false), name_(name)
    {
    }
    ~Timer()
    {
        Stop();
    }

    void Start(int interval, std::function<void()> callback)
    {
        if (running_)
        {
            std::cerr << "Timer already running" << std::endl;
            return;
        }

        running_ = true;
        thread_  = std::thread([=]() {
            ///< 上次时间戳
            uint64_t last_ts = GetMilliSec();
            uint64_t period  = interval * 1000;
            ///< 精度
            uint64_t accuracy = 200;
            while (running_)
            {
                if (period > accuracy)
                {
                    uint64_t now = GetMilliSec();
                    if ((uint64_t)Abs<int64_t>(now - last_ts) < period)
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(accuracy));
                        continue;
                    }
                    last_ts = now;
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(interval));
                }
                callback();
            }
        });
    }

    void Stop()
    {
        running_ = false;
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

private:
    std::string name_;
    bool running_;
    std::thread thread_;
};

#endif
