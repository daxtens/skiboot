// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef LOG_H
#define LOG_H

/* Console logging
 * Update console_get_level() if you add here
 */
#define PR_EMERG	0
#define PR_ALERT	1
#define PR_CRIT		2
#define PR_ERR		3
#define PR_WARNING	4
#define PR_NOTICE	5
#define PR_PRINTF	PR_NOTICE
#define PR_INFO		6
#define PR_DEBUG	7
#define PR_TRACE	8
#define PR_INSANE	9

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

void _prlog(int log_level, const char* fmt, ...) __attribute__((format (printf, 2, 3)));
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)
#define prerror(fmt...)	do { prlog(PR_ERR, fmt); } while(0)
#define prlog_once(arg, ...)	 		\
({						\
	static bool __prlog_once = false;	\
	if (!__prlog_once) {			\
		__prlog_once = true;		\
		prlog(arg, ##__VA_ARGS__);	\
	}					\
})

#endif