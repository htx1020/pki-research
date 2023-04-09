#ifndef LOG_H
#define LOG_H
#include <time.h>
#include <unistd.h>


#define NONE                 "\33[0m"
#define BLACK                "\33[0;30m"
#define L_BLACK              "\33[1;30m"
#define RED                  "\33[0;31m"
#define L_RED                "\33[1;31m"
#define GREEN                "\33[0;32m"
#define L_GREEN              "\33[1;32m"
#define BROWN                "\33[0;33m"
#define YELLOW               "\33[1;33m"
#define BLUE                 "\33[0;34m"
#define L_BLUE               "\33[1;34m"
#define PURPLE               "\33[0;35m"
#define L_PURPLE             "\33[1;35m"
#define CYAN                 "\33[0;36m"
#define L_CYAN               "\33[1;36m"
#define GRAY                 "\33[0;37m"
#define WHITE                "\33[1;37m"

#define BOLD                 "\33[1m"
#define UNDERLINE            "\33[4m"
#define BLINK                "\33[5m"
#define REVERSE              "\33[7m"
#define HIDE                 "\33[8m"
#define CLEAR                "\33[2J"
#define CLRLINE              "\r\33[2K" //or "\e[1K\r""]]"

#define STREAM_SELECT stderr

#define FOR_LOG_BASE(st) getpid(), st.tm_year + 1900, st.tm_mon + 1, st.tm_mday, st.tm_hour, st.tm_min, st.tm_sec, __FUNCTION__ , __LINE__

#define log_inf(format, ...)                                                       \
{                                                                                   \
    time_t t = time(0); struct tm st = *localtime(&t);                              \
    fprintf(STREAM_SELECT, "\033[32m[INF][%5d %4d-%02d-%02d %02d:%02d:%02d] [%s:%d]" format "\033[0m", FOR_LOG_BASE(st), ##__VA_ARGS__); \
}

#define log_err(format, ...)                                                       \
{                                                                                   \
    time_t t = time(0); struct tm st = *localtime(&t);                              \
    fprintf(STREAM_SELECT, "\033[31m[ERR][%5d %4d-%02d-%02d %02d:%02d:%02d] [%s:%d]" format "\033[0m", FOR_LOG_BASE(st), ##__VA_ARGS__); \
}

#define log_dbg(format, ...)                                                       \
{                                                                                   \
    time_t t = time(0); struct tm st = *localtime(&t);                              \
    fprintf(STREAM_SELECT, "\033[34m[DBG][%5d %4d-%02d-%02d %02d:%02d:%02d] [%s:%d]" format "\033[0m", FOR_LOG_BASE(st), ##__VA_ARGS__); \
}

#define hexdump(title, _p, _len)  \
    do{ \
        unsigned char *p = _p; \
        fprintf(STREAM_SELECT, "\033[34m[%s]\033[0m %d|", title, _len); \
        for(int _i=0; _i<(int)(_len); _i++) { \
            fprintf(STREAM_SELECT, "%02X", (unsigned char)*p++); \
        }\
        fprintf(STREAM_SELECT, "|\n"); \
    }while(0)

#endif 
