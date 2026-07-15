#ifndef CAPTURE
#define CAPTURE

#include <stdint.h>
#include <sys/types.h>

extern void capture (pid_t pid, uint32_t scmp_arch);

#endif
