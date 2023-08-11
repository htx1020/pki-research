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
 * @file utils.h
 * @brief 工具集
 * @details 常用的工具函数集合
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
#ifndef LIC_COMMON_UTILS_H_
#define LIC_COMMON_UTILS_H_

#include <stddef.h>

#include <cwchar>
#include <iostream>
#include <time.h>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <bits/types/time_t.h>
#include <unistd.h>
#elif _WIN32
#include <io.h>
#define F_OK 0
#endif

namespace utils {

///<  配置算法标识符号 sha256WithRSAEncryption
extern uint8_t kAlgoIdentifier[9];

typedef struct
{
    std::string title;
    std::string data;
} DataOfPem;

int Base64Encode(const unsigned char *text, int text_len, char *encode);

int Base64Decode(const char *code, int code_len, unsigned char *plain);

int WriteDataToPem(const char *file, const char *title, uint8_t *data, size_t len);

int ReadDataToPem(const char *file, DataOfPem &data);

time_t GetNowTimeStamp();

std::string GetTimeString();

std::string TransformTimeStamp(time_t ts);

std::string ByteToHexString(const void *data, size_t size);

std::vector<uint8_t> FromHexStr(const char *str);

std::string GetDirectOfPath(std::string file);
std::string GetFileNameOfPath(std::string file);
void MakeDirectory(const std::string &dir);

bool IsAccess(const std::string &file);
std::string InsertCharacter(const std::string &str, char ch, int interval = 60);

time_t GetTimeStampByArray(uint8_t data[8]);
void GetArrayByTimeStamp(time_t time_stamp, uint8_t data[8]);

time_t UTCToTimeStamp(const struct tm &time_body);

int GetTimeZoneOffset();
///< 获取CST（中国标准时间）时间字符串
struct tm CSTFromTimeStamp(const time_t &ts);
time_t CSTToTimeStamp(const struct tm &time_body);
std::string ToTimeString(const struct tm &time_body);
time_t TimeCalcDiffYear(const time_t &time_stamp, int diff_years);

void ToUpper(std::string &str);
} // namespace utils
#endif // LIC_COMMON_UTILS_H_
