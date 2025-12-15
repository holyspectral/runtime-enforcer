#pragma once

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#ifndef memset
#define memset(s, c, n) __builtin_memset((s), (c), (n))
#endif

#ifndef memcpy
#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n))
#endif

#ifndef memmove
#define memmove(d, s, n) __builtin_memmove((d), (s), (n))
#endif
