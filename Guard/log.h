#ifndef GUARD_LOG_H
#define GUARD_LOG_H

#if DEBUG
#define LOG_MSG(format, ...)  DbgPrint("FIM : " format "\n\r" __VA_OPT__(,) __VA_ARGS__)
#else
#define LOG_MSG(format, ...) 
#endif

#define LOG_ALLOC LOG_MSG("%s %")

#endif //GUARD_LOG_H


