#ifndef STDBOOL_H
#define STDBOOL_H
#include <BaseTsd.h>

// We use VC++, VC only supports C89 and the BUFFER Macros are really a mess
#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
# define _SSIZE_T_
# define _SSIZE_T_DEFINED
#endif

#endif // STDBOOL_H
