#ifndef __EZDM_PAM_H__
#define __EZDM_PAM_H__

#include <stdbool.h>

bool login(const char *username, const char *password, pid_t *child_pid);
bool logout(void);
void err(const char *msg, int result);

#endif
