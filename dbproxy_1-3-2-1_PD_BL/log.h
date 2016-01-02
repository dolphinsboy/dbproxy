#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_NONE_LEVEL 0
#define LOG_ERROR_LEVEL 1
#define LOG_WARNING_LEVEL 2
#define LOG_WORK_LEVEL 4
#define LOG_LOAD_LEVEL 8
#define LOG_DEBUG_LEVEL 16

#define LOG_WORK "WORK"
#define LOG_DEBUG "DEBUG"
#define LOG_WARNING "WARNING"
#define LOG_ERROR "ERROR"
#define LOG_LOAD "LOAD"

#define MAX_LOG_SQL_LEN 512
#define LEFT_LOG_SQL_LEN 400
#define RIGHT_LOG_SQL_LEN 105
#define LOG_BUF_SIZE 2048

enum{
	LOG_WORK_TYPE_CONN,
	LOG_WORK_TYPE_QURY,
	LOG_WORK_TYPE_QUIT
} log_work_type;

typedef struct{

	unsigned long int  maxsize;
	char *log_dir;
	char *log_filename;

	char *log_filepath;
	char *werror_log_filepath;
	char *load_log_filepath;

	char *log_filepath_tmp;
	char *werror_log_filepath_tmp;
	char *load_log_filepath_tmp;

	ino_t log_inode;
	ino_t werror_log_inode;
	ino_t load_log_inode;

	int fd;
	int werror_fd;
	int load_fd;

	int log_level;

} t_logger;

t_logger *logger;

extern t_logger* logger_create(char *log_dir, char *log_filename, int maxsize, int log_level);
extern void logger_close(t_logger *logger);
extern void logger_write(t_logger *logger, const char *level, const char *fmt, ...);
extern void log_write(t_logger *logger, int log_type, int level_num, const char *fmt, ...);
extern void truncate_str_two_ends(char *dest, char *src, int src_len);

inline long getuseconds();
/*
#define log_func_in(logger)  \
	log_write(logger, 0, "[TIME:%lu us][INFO][%s][%s][LINE:%d][PID:%d]\n[message]:WALK_INTO_FUNCTION :%s\n", \
			getuseconds(), __FILE__, __PRETTY_FUNCTION__, __LINE__, getpid(), __PRETTY_FUNCTION__)

#define log_func_out(logger)  \
	log_write(logger, 0, "[TIME:%lu us][INFO][%s][%s][LINE:%d][PID:%d]\n[message]:WALK_OUTOF_FUNCTION :%s\n", \
			getuseconds(), __FILE__, __PRETTY_FUNCTION__, __LINE__, getpid(), __PRETTY_FUNCTION__)

*/
#define log_error(logger, fmt, arg...)  \
	log_write(logger, 1, 0x01, \
			"[ERROR][%s][%s][LINE:%d][PID:%d] " fmt "%s", \
			__FILE__, __PRETTY_FUNCTION__, __LINE__, getpid(), ## arg, "\n")

#define log_warning(logger, fmt, arg...)  \
	log_write(logger, 1, 0x02, \
			"[WARNING][%s][%s][LINE:%d][PID:%d] " fmt "%s", \
			__FILE__, __PRETTY_FUNCTION__, __LINE__, getpid(), ## arg, "\n")
/*
#define log_work(logger, fmt, arg...)  \
	log_write(logger, 0, 0x04, fmt "%s", ## arg, "\n")
*/
#define log_load(logger, fmt, arg...)  \
	log_write(logger, 2, 0x08, fmt "%s", ## arg, "\n")

#define log_debug(logger, fmt, arg...)  \
	log_write(logger, 1, 0x10, \
			"[DEBUG][%s][%s][LINE:%d][PID:%d] " fmt "%s", \
			__FILE__, __PRETTY_FUNCTION__, __LINE__, getpid(), ## arg, "\n")

#endif
