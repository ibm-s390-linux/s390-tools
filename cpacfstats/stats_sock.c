/*
 * cpacfstats - display and maintain CPACF perf counters
 *
 * basic socket and receive/send functions
 *
 * Copyright IBM Corp. 2015, 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <grp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "cpacfstats.h"


int open_socket(int mode)
{
	struct sockaddr_un sock_addr;
	struct group *grp;
	mode_t m;
	int s;

	/* group handling */
	grp = getgrnam(CPACFSTATS_GROUP);
	if (!grp) {
		eprint("Getgrnam() failed, group '%s' may not exist on this system ?\n",
		       CPACFSTATS_GROUP);
		return -1;
	}

	/* the client checks for the unix domain socket file */
	if (mode != SERVER) {
		if (access(SOCKET_FILE, F_OK) != 0) {
			eprint("Can't access domain socket file '%s', errno=%d [%s]\n",
			       SOCKET_FILE, errno, strerror(errno));
			if (errno == ENOENT)
				eprint("Maybe cpacfstatsd daemon is not running ???\n");
			return -1;
		}
	}

	/* create socket */
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s == -1) {
		eprint("Socket(AF_UNIX,SOCK_STREAM) failed, errno=%d [%s]\n",
		       errno, strerror(errno));
		return -1;
	}

	if (mode == SERVER)
		remove(SOCKET_FILE);

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, SOCKET_FILE, sizeof(sock_addr.sun_path));
	sock_addr.sun_path[sizeof(sock_addr.sun_path)-1] = '\0';

	if (mode == SERVER) {
		if (bind(s, (struct sockaddr *) &sock_addr,
			 sizeof(struct sockaddr_un)) < 0) {
			eprint("Bind('%s') failed, errno=%d [%s]\n",
			       SOCKET_FILE, errno, strerror(errno));
			return -1;
		}
		/* change group ownership of the socket file */
		if (chown(SOCKET_FILE, 0, grp->gr_gid)) {
			eprint("Chown('%s',...) failed, errno=%d [%s]\n",
			       SOCKET_FILE, errno, strerror(errno));
			return -1;
		}
		/* adapt permissions */
		m = S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IWGRP|S_IXGRP;
		if (chmod(SOCKET_FILE, m)) {
			eprint("Chmod('%s',...) failed, errno=%d [%s]\n",
			       SOCKET_FILE, errno, strerror(errno));
			return -1;
		}
		/* now put the socket into listen state */
		if (listen(s, BACKLOG) < 0) {
			eprint("Listen() failed, errno=%d [%s]\n",
			       errno, strerror(errno));
			return -1;
		}
	} else {
		if (connect(s, (struct sockaddr *) &sock_addr,
			    sizeof(sock_addr)) < 0) {
			eprint("Connect() failed, errno=%d [%s]\n",
			       errno, strerror(errno));
			return -1;
		}
	}

	return s;
}


static int __write(int fd, const void *buf, int buflen)
{
	const unsigned char *p = buf;
	int n, i = 0;

	while (i < buflen) {
		n = write(fd, p+i, buflen-i);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else
				return n;
		}
		i += n;
	}

	return i;
}


static int __read(int fd, void *buf, int buflen)
{
	unsigned char *p = buf;
	int n, i = 0;

	while (i < buflen) {
		n = read(fd, p+i, buflen-i);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else
				return n;
		} else if (n == 0) {
			return i;
		} else {
			i += n;
		}
	}

	return i;
}


static int __timedwrite(int fd, const void *buf, int buflen, int timeout)
{
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int i = 0, n;

	while (poll(&pfd, 1, timeout) == 1) {
		n = write(fd, buf + i, buflen - i);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else
				return n;
		} else if (n == 0) {
			return i;
		}
		i += n;
		if (buflen == i)
			return i;
	}
	return -1;
}

static int __timedread(int fd, void *buf, int buflen, int timeout)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int i = 0, n;

	while (poll(&pfd, 1, timeout) == 1) {
		n = read(fd, buf + i, buflen - i);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else
				return n;
		} else if (n == 0) {
			return i;
		}
		i += n;
		if (buflen == i)
			return i;
	}
	return -1;
}

int send_msg(int sfd, struct msg *m, int timeout)
{
	int n, len;

	len = sizeof(m->head);

	switch (m->head.m_type) {
	case QUERY:
		len += sizeof(m->query);
		break;
	case ANSWER:
		len += sizeof(m->answer);
		break;
	default:
		eprint("Unknown type %d\n", m->head.m_type);
		return -1;
	}

	n = timeout ? __timedwrite(sfd, m, len, timeout) : __write(sfd, m, len);
	if (n != len) {
		eprint("Write() error: write()=%d expected %d, errno=%d [%s]\n",
		       n, len, errno, strerror(errno));
		return -1;
	}

	return 0;
}

int recv_msg(int sfd, struct msg *m, int timeout)
{
	int n, len;

	len = sizeof(m->head);
	n = timeout ? __timedread(sfd, m, len, timeout) : __read(sfd, m, len);
	if (n != len) {
		eprint("Recv() error: read()=%d expected %d, errno=%d [%s]\n",
		       n, len, errno, strerror(errno));
		return -1;
	}

	switch (m->head.m_type) {
	case QUERY:
		len = sizeof(m->query);
		break;
	case ANSWER:
		len = sizeof(m->answer);
		break;
	default:
		eprint("Unknown type %d\n", m->head.m_type);
		return -1;
	}

	n = timeout ? __timedread(sfd, ((char *)m) + sizeof(m->head), len, timeout) :
		__read(sfd, ((char *)m) + sizeof(m->head), len);
	if (n != len) {
		eprint("Recv() error: recv()=%d expected %d, errno=%d [%s]\n",
		       n, len, errno, strerror(errno));
		return -1;
	}

	return 0;
}
