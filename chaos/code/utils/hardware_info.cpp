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
 * @file hardware_info.cpp
 * @brief 硬件信息
 * @details 获取硬件信息
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
#include "hardware_info.h"


#include <string.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <vector>

namespace utils {

#if defined(__linux__) || defined(__APPLE__)
#include <bits/types/FILE.h>
#include <unistd.h>
// Commander
const char cmd_info_disk[] = "blkid $(df /etc | awk 'NR==2 {print $1}') | awk '{print $2}'";
const char cmd_info_mac[]  = "lshw -c network | grep serial | head -n 1";
const char cmd_info_mainboard[] =
    "dmesg | grep UUID | grep \"Kernel\" | sed \"s/.*UUID=//g\" | sed \"s/\\ ro\\ quiet.*//g\"";

typedef std::string (*CbHandleFilePointer)(FILE *fp);

inline void ExeCmd(const char *cmd, std::string &rval, CbHandleFilePointer handle)
{
    FILE *fp = popen(cmd, "r"); // 执行命令行并打开管道
    rval     = handle(fp);
    pclose(fp); // 关闭管道
}

inline void ExeCmd(const char *cmd, std::vector<std::string> &rval)
{
    FILE *fp          = popen(cmd, "r"); // 执行命令行并打开管道
    char buffer[1024] = {0};
    ///< 从管道读取结果
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        // 处理结果
        std::string cell(buffer);
        if (cell.size() != 0)
        {
            rval.emplace_back(cell);
        }
        buffer[0] = 0;
    }
    pclose(fp); // 关闭管道
}

std::string GetMainBoard()
{
    std::string rval;
    ExeCmd(cmd_info_mainboard, rval, [](FILE *fp) {
        char buffer[1024] = {0};
        fgets(buffer, sizeof(buffer), fp);
        return std::string(buffer);
    });
    return rval;
}

static std::string GetDiskInfo()
{
    std::string rval;
    ExeCmd(cmd_info_disk, rval, [](FILE *fp) {
        char buffer[1024] = {0};
        while (fgets(buffer, sizeof(buffer), fp) != NULL)
        { // 从管道读取结果
            if (NULL != strstr(buffer, "UUID"))
            {
                break;
            }
            buffer[0] = 0;
            // 处理结果
        }
        return std::string(buffer);
    });
    return rval;
}

static std::string GetCpuInfo()
{
    std::string cpuInfo;
    std::ifstream cpuFile("/proc/cpuinfo");
    while (getline(cpuFile, cpuInfo))
    {
        if (cpuInfo.find("model name") != std::string::npos)
        {
            return cpuInfo;
        }
    }
    return "";
}

static std::string GetEthInfo()
{
    std::string rval;
    ExeCmd(cmd_info_mac, rval, [](FILE *fp) {
        char buffer[1024] = {0};
        while (fgets(buffer, sizeof(buffer), fp) != NULL)
        { // 从管道读取结果
            if (NULL != strstr(buffer, "serial"))
            {
                break;
            }
            buffer[0] = 0;
            // 处理结果
        }
        return std::string(buffer);
    });
    size_t pos = rval.find("\n");
    return rval;
}

static std::string GetHostInfo()
{
    char hostname[256] = {};
    gethostname(hostname, sizeof(hostname));
    return hostname;
}

std::string GetHardWareInfo()
{
    std::stringstream ss;
    ss << GetMainBoard() << "|";
    ss << GetEthInfo() << "|";
    ss << GetCpuInfo() << "|";
    ss << GetDiskInfo() << "|";
    //ss << GetHostInfo() << "|";
    std::string val = ss.str();
    val             = std::regex_replace(val, std::regex("\r\n|\n| |\t"), "");
    return val;
}

#elif _WIN32
#if 0
/* char* get_cpuid(char *pCpuId) */
std::string GetCpuInfo() {
{
    unsigned int dwBuf[4];
    getcpuid(dwBuf, 1);
    char tmp[36];
    sprintf(tmp, "%08X", dwBuf[3]);
    sprintf(tmp + 8, "%08X", dwBuf[0]);
    return tmp;
}

void getcpuid(unsigned int *CPUInfo, unsigned int InfoType)
{
#if defined(__GNUC__)   // GCC
    __cpuid(InfoType, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
#elif defined(_MSC_VER) // MSVC
#if _MSC_VER >= 1400    // VC2005才支持__cpuid
    __cpuid((int*)(void*)CPUInfo, (int)(InfoType));
#else                   // 其他使用getcpuidex
    getcpuidex(CPUInfo, InfoType, 0);
#endif
#endif
}

void getcpuidex(unsigned int *CPUInfo, unsigned int InfoType, unsigned int ECXValue)
{
#if defined(_MSC_VER) // MSVC
#if defined(_WIN64)   // 64位下不支持内联汇编. 1600: VS2010, 据说VC2008 SP1之后才支持__cpuidex.
    __cpuidex((int*)(void*)CPUInfo, (int)InfoType, (int)ECXValue);
#else
    if (NULL == CPUInfo)
        return;
    _asm {
        // load. 读取参数到寄存器.
        mov edi, CPUInfo;
        mov eax, InfoType;
        mov ecx, ECXValue;
        // CPUID
        cpuid;
        // save. 将寄存器保存到CPUInfo
        mov[edi], eax;
        mov[edi + 4], ebx;
        mov[edi + 8], ecx;
        mov[edi + 12], edx;
    }
#endif
#endif
}
#endif

// #include <stdio.h>
std::string PlatWinShell(std::string &cmd)
{
    char buffer[128];
    FILE *pipe = _popen(cmd.c_str(), "r"); // 假设要运行的命令为 dir
    if (!pipe)
        return "";
    std::stringstream ss;
    while (fgets(buffer, sizeof buffer, pipe))
    {
        ss << buffer;
        // 处理命令的输出数据，比如打印到控制台上
        // printf("==%s", buffer);
    }
    std::string val = ss.str();
    val             = std::regex_replace(val, std::regex("\r\n|\n| |\t"), "");
    _pclose(pipe); // 关闭进程
    return val;
}

std::string GetHardWareInfo()
{
    std::string cmds[] = {"wmic diskdrive get serialnumber", "wmic BASEBOARD get serialnumber",
                          "wmic cpu get processorid", "wmic csproduct get uuid"};
    std::stringstream ss;
    for (auto &i : cmds)
    {
        ss << PlatWinShell(i) << "|";
    }
    return ss.str();
}

#endif

} // namespace utils
