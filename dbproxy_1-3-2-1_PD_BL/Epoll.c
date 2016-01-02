#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "Epoll.h"
#include "network.h"


/**
 * @brief ����poll�ṹ��
 * @return �����ɹ����򷵻�poll�ṹ�壬���򷵻�NULL
 */
extern poll* poll_create(){

	poll *p;
	if( NULL == (p = calloc(1, sizeof(poll)))){
		log_error(logger, "calloc memory failed, need %d bytes, no enough memory", sizeof(poll));
		return NULL;
	}

	p->event_size = CONFIG_MPL_EPOLL_MAX_SIZE;

	if( 0 > (p->epfd = epoll_create(CONFIG_MPL_EPOLL_MAX_SIZE))){
		log_error(logger, "epoll_create() failed");
		return NULL;
	}
	
	p->max_fd = -1;
	return p;
}

/**
 * @brief �޸�epoll�¼�
 * @param p poll�ṹ��
 * @param s network_socket�ṹ��
 * @param events epoll�¼�
 * @return �޸ĵĽ��
 */
extern int poll_events_mod(poll *p, network_socket *s, unsigned int events){
	int flag = 0;
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	if(events & EPOLLIN) {
	    ev.events |= EPOLLIN;
	}
	if(events & EPOLLOUT) {
	    ev.events |= EPOLLOUT;
	}
	ev.events |= EPOLLERR | EPOLLHUP;
	ev.data.fd = s->fd;

	if( 0 > epoll_ctl(p->epfd, EPOLL_CTL_MOD, s->fd, &ev)){
		log_error(logger, "epoll_ctl failed, epfd=%d, fd=%d, errno=%d, error:%s", p->epfd, s->fd, errno, strerror(errno));
		flag = -1;
	}
	return flag;
}

/**
 * @brief ��s�е�fd�ӵ�epoll��
 * @param p poll�ṹ��
 * @param s ����fd��network_socket�ṹ��
 * @param events epoll event
 * @return ���ӵĽ��
 */
extern int poll_events_add(poll *p, network_socket *s, unsigned int events){

	int flag = 0;
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	if(events & EPOLLIN) {
	    ev.events |= EPOLLIN;
	}
	if(events & EPOLLOUT) {
	    ev.events |= EPOLLOUT;
	}
	ev.events |= EPOLLERR | EPOLLHUP;
	ev.data.fd = s->fd;

	if( 0 > epoll_ctl(p->epfd, EPOLL_CTL_ADD, s->fd, &ev)){
		log_error(logger, "epoll_ctl, epfd=%d, fd=%d, errno=%d, error:%s", p->epfd, s->fd, errno, strerror(errno));
		flag = -1;
	}
	if(p->max_fd < s->fd){
		p->max_fd = s->fd;
	}
	return flag;
}

/**
 * @brief ��fd��epoll��ɾ��
 * @param p poll�ṹ��
 * @param s ����fd��network_socket�ṹ��
 * @return ɾ���Ľ��
 */
extern int poll_events_delete(poll *p, network_socket *s){

	int flag = 0;
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.data.fd = s->fd;

	if( 0 > epoll_ctl(p->epfd, EPOLL_CTL_DEL, s->fd, &ev)){
		log_error(logger, "epoll_ctl, epfd=%d, fd=%d, errno=%d, error:%s", p->epfd, s->fd, errno, strerror(errno));
		flag = -1;
	}
	if(s->fd >= p->max_fd){
		int i;
		int f = 0;
		for( i = s->fd - 1; i >=0; i --){
			if( NULL !=  p->fd_mapping[i]){
				p->max_fd = i;
				f = 1;
				break;
			}
		}
		if(f == 0) {
		    p->max_fd = -1;
		}
	}
	return flag;
}
