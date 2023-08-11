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
#include "utils.h"

#include <algorithm>
#include <assert.h>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <experimental/filesystem>

#if defined(__linux__) || defined(__APPLE__)
#include <cerrno>
#include <sys/stat.h>
#elif _WIN32
#include <direct.h>
#endif

#ifdef _WIN32
#define timegm _mkgmtime
#endif

namespace utils {

///< 8个时区的差值（秒）
const time_t kHourSeconds = 3600;
const int kCstTimeZone    = 8;

///<  配置算法标识符号 sha256WithRSAEncryption
uint8_t kAlgoIdentifier[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};

///< Base64字符集
static unsigned char alphabet_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char reverse_map[] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,
    255, 255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255, 255, 255, 255, 255, 255, 0,
    1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,
    23,  24,  25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
    39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  255, 255, 255, 255, 255};

int Base64Encode(const unsigned char *text, int text_len, char *encode)
{
    int i, j;
    for (i = 0, j = 0; i + 3 <= text_len; i += 3)
    {
        encode[j++] = alphabet_map[text[i] >> 2]; // 取出第一个字符的前6位并找出对应的结果字符
        encode[j++] =
            alphabet_map[((text[i] << 4) & 0x30)
                         | (text[i + 1] >> 4)]; // 将第一个字符的后2位与第二个字符的前4位进行组合并找到对应的结果字符
        encode[j++] =
            alphabet_map[((text[i + 1] << 2) & 0x3c)
                         | (text[i + 2] >> 6)]; // 将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符
        encode[j++] = alphabet_map[text[i + 2] & 0x3f]; // 取出第三个字符的后6位并找出结果字符
    }

    if (i < text_len)
    {
        int tail = text_len - i;
        if (tail == 1)
        {
            encode[j++] = alphabet_map[text[i] >> 2];
            encode[j++] = alphabet_map[(text[i] << 4) & 0x30];
            encode[j++] = '=';
            encode[j++] = '=';
        }
        else // tail==2
        {
            encode[j++] = alphabet_map[text[i] >> 2];
            encode[j++] = alphabet_map[((text[i] << 4) & 0x30) | (text[i + 1] >> 4)];
            encode[j++] = alphabet_map[(text[i + 1] << 2) & 0x3c];
            encode[j++] = '=';
        }
    }
    return j;
}

int Base64Decode(const char *code, int code_len, unsigned char *plain)
{
    // assert((code_len&0x03) == 0)
    if ((code_len & 0x03) != 0)
        return -1; // 如果它的条件返回错误，则返回。4的倍数。

    int i, j = 0;
    unsigned char quad[4];
    for (i = 0; i < code_len; i += 4)
    {
        for (int k = 0; k < 4; k++)
        {
            quad[k] = reverse_map[code[i + k]]; // 分组，每组四个分别依次转换为base64表内的十进制数
        }

        // assert(quad[0]<64 && quad[1]<64);
        if (quad[0] >= 64 || quad[1] >= 64)
        {
            return -1;
        }

        plain[j++] =
            (quad[0] << 2)
            | (quad[1]
               >> 4); // 取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的前2位进行组合

        if (quad[2] >= 64)
            break;
        else if (quad[3] >= 64)
        {
            plain[j++] =
                (quad[1] << 4)
                | (quad[2]
                   >> 2); // 取出第二个字符对应base64表的十进制数的后4位与第三个字符对应base64表的十进制数的前4位进行组合
            break;
        }
        else
        {
            plain[j++] = (quad[1] << 4) | (quad[2] >> 2);
            plain[j++] = (quad[2] << 6) | quad[3]; // 取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合
        }
    }
    return j;
}

int WriteDataToPem(const char *file, const char *title, uint8_t *data, size_t len)
{
    size_t encodeLen = (size_t)len * 2;
    std::unique_ptr<char[]> encode(new char[encodeLen]);
    memset(encode.get(), 0, encodeLen);
    Base64Encode(data, (int)len, encode.get());
    std::string body = InsertCharacter(encode.get(), '\n', 70);
    std::ofstream output(file);
    output << "-----BEGIN " << title << "-----\n" << body << "\n-----END " << title << "-----\n";
    output.close();
    return 0;
}

int ReadDataToPem(const char *file, DataOfPem &data)
{
    std::ifstream input(file);
    std::string line;
    std::string base64_data;

    bool flag_start = false;
    while (std::getline(input, line))
    {
        std::size_t pos = line.find("-----BEGIN ");
        if (std::string::npos != pos)
        {
            std::size_t pos_end = line.find_last_of("-----");
            std::string tmps;
            if (std::string::npos != pos_end)
            {
                pos_end -= strlen("-----") - 1;
                // 开始提取TITLE字段
                std::size_t pos_start = strlen("-----BEGIN ");
                tmps                  = line.substr(pos_start, (pos_end - pos_start));
            }
            data.title = tmps;
            flag_start = true;
            continue;
        }
        if (std::string::npos != line.find("-----END"))
        {
            // 字段提取结束
            break;
        }
        if (flag_start)
        {
            // License data...
            base64_data += line;
        }
    }
    input.close();

    base64_data.erase(remove(base64_data.begin(), base64_data.end(), '\n'), base64_data.end());
    std::unique_ptr<uint8_t[]> bare_data(new uint8_t[base64_data.size()]);
    int ret = Base64Decode(base64_data.c_str(), (int)base64_data.size(), bare_data.get());
    if (ret <= 0)
    {
        return -3;
    }
    data.data.assign((char *)bare_data.get(), ret);

    return 0;
}

std::string GetTimeString()
{
    // 获取当前时间点
    auto now = std::chrono::system_clock::now();
    // 转换为时间戳,以秒为单位
    auto timestamp = std::chrono::system_clock::to_time_t(now);
    // 转换为tm时间结构
    struct tm *ptm = localtime(&timestamp);
    // 转换为时间字符串
    std::stringstream ss;
    ss << std::put_time(ptm, "%Y%m%d%H%M%S");
    return ss.str();
}

time_t GetNowTimeStamp()
{
    return time(NULL);
}

std::string TransformTimeStamp(time_t ts)
{
    char tmp[64]        = "";
    struct tm *timeinfo = localtime(&ts);
    strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", timeinfo);
    return tmp;
}

std::string ByteToHexString(const void *data, size_t size)
{
    uint8_t *p = (uint8_t *)data;
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; i++)
    {
        ss << std::setw(2) << static_cast<int>(p[i]);
    }
    return ss.str();
}

std::vector<uint8_t> FromHexStr(const char *str)
{
    std::vector<uint8_t> rval;
    if (!str)
        return rval;
    char *p  = (char *)str;
    size_t l = strlen(p);
    while (l--)
    {
        uint8_t val;
        val = (*p > '9' ? *(p++) + 9 : *(p++)) << 4;
        val |= ((*p > '9' ? *(p++) + 9 : *(p++)) & 0x0F);
        rval.emplace_back(val);
    }
    return rval;
}

std::string GetDirectOfPath(std::string file)
{
    std::experimental::filesystem::path p(file);
    return p.parent_path().string();
}

std::string GetFileNameOfPath(std::string file)
{
    std::experimental::filesystem::path p(file);
    return p.filename().string();
}

bool IsAccess(const std::string &file)
{
    return F_OK == access(file.c_str(), F_OK);
}

std::string InsertCharacter(const std::string &str, char ch, int interval)
{
    std::string result;
    int count = 0;
    for (char c : str)
    {
        result += c;
        count++;
        if ((count % interval == 0) && (count != str.size()))
        {
            result += ch;
        }
    }
    return result;
}

time_t GetTimeStampByArray(uint8_t data[8])
{
    assert(sizeof(time_t) <= 8);
    time_t t;
    memcpy(&t, data, sizeof(time_t));
    return t;
}

void GetArrayByTimeStamp(time_t time_stamp, uint8_t data[8])
{
    assert(sizeof(time_t) <= 8);
    memcpy(data, &time_stamp, sizeof(time_t));
}

int GetTimeZoneOffset()
{
    time_t sample      = 10000;
    struct tm local_tm = *localtime(&sample);
    struct tm gm_tm    = *gmtime(&sample);
    return local_tm.tm_hour - gm_tm.tm_hour;
}

struct tm CSTFromTimeStamp(const time_t &ts)
{
    time_t new_ts = ts + kHourSeconds * kCstTimeZone;
    std::tm utcTime{};
#if defined(__linux__)
    gmtime_r(&new_ts, &utcTime);
#elif _WIN32
    gmtime_s(&utcTime, &new_ts);
#endif

    return utcTime;
}

time_t UTCToTimeStamp(const struct tm &time_body)
{
    struct tm time_b = time_body;
    return timegm(&time_b);
}

time_t CSTToTimeStamp(const struct tm &time_body)
{
    int diff         = kHourSeconds * (kCstTimeZone);
    struct tm time_b = time_body;
    return timegm(&time_b) - diff;
}

time_t TimeCalcDiffYear(const time_t &time_stamp, int diff_years)
{
    struct tm time_body = CSTFromTimeStamp(time_stamp);
    time_body.tm_year += diff_years;
    return CSTToTimeStamp(time_body);
}

std::string ToTimeString(const struct tm &time_body)
{
    char s[64];
    strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", &time_body);
    return s;
}

void MakeDirectory(const std::string &dir)
{
#ifdef _WIN32
    _mkdir(dir.c_str());
#else
    mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

#endif
}

void ToUpper(std::string &str)
{
    for (char &i : str)
    {
        i = (char)toupper(i);
    }
}

} // namespace utils
