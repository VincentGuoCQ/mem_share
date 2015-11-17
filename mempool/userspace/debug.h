#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define USE_DEBUG

#ifdef USE_DEBUG

#define DEBUG_LINE printf("[%s:%s] line=%d\r\n", __FILE__, __func__, __LINE__)
#define DEBUG_ERR(fmt, args...) printf("\033[42;33m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_INFO(fmt, args...) printf("\033[42;33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)

#else

#define DEBUG_LINE()
#define DEBUG_ERR(fmt, ...)
#define DEBUG_INFO(fmt,...)

#endif //USE_DEBUG

#define PRINT_INFO(fmt, args...) printf(fmt, ##args)

#endif //DEBUG_H
