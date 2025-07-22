#ifndef GUARD_LOG_H
#define GUARD_LOG_H

#if 1
#define LOG_MSG(format, ...) DbgPrint("FIM : " format "\n\r" __VA_OPT__(,) __VA_ARGS__)
#else
#define LOG_MSG(format, ...) 
#endif

#define LOG_ALLOC DbgPrint("%s %")

#endif //GUARD_LOG_H
