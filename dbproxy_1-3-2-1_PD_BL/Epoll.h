#ifndef _POOL_H_
#define _POOL_H_

#include <glib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include "config.h"

/**
 * @brief epoll ³¬Ê±Ê±¼ä
 */
#define EPOLL_TIMEOUT 2000
typedef struct {
	void *fd_mapping[CONFIG_MPL_EPOLL_MAX_SIZE];
//	int cur_size;
	int max_fd;
	int epfd;
	struct epoll_event events[CONFIG_MPL_EPOLL_MAX_SIZE];
	size_t event_size;
} poll;

extern poll* poll_create();

#endif
