/*
 * util - Utility function library
 *
 * Created file-based locks
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "lib/util_libc.h"
#include "lib/util_lockfile.h"
#include "lib/util_panic.h"

#define WAITPID 120 /* Time to wait for pid to be written */
#define WAITINC 5   /* Additional time to wait each retry */
#define MAXWAIT 60  /* Maximum wait between retries */
#define BUFSIZE 40  /* Buffer must be large enough to fit pid string */

/**
 * Check if there is a process that exists with the specified identifier.
 *
 * @param[in]      pid        Process Identifier to check
 *
 * @retval         true       Process exists or we lack privelege to check
 * @retval         false      Process does not exist
 */
static bool pid_exists(int pid)
{
	int rc;

	/* Use sig 0 to determine if the owner is still alive */
	rc = kill(pid, 0);
	if (rc != 0) {
		switch (errno) {
		case EPERM:
			/* Privilege issue, just assume PID exists */
			break;
		case ESRCH:
			/* PID does not exist, this lock is stale */
			return false;
		default:
			util_assert(false, "Unexpected return from kill: %d\n", rc);
			break;
		}
	}

	return true;
}

/**
 * Check for an existing lock that is deemed stale (either the associated PID
 * is gone or no PID has been written to the file in a reasonable timeframe).
 * In the case a stale lock is found, remove it.
 *
 * @param[in]      lockfile   Path to the lock file
 *
 * @retval         0          Either no lock or stale lock was found and removed
 * @retval         1          Lock is held by another PID and is not stale
 */
static int handle_stale_lock(char *lockfile)
{
	int fd, rc, pid, len;
	struct stat info;
	char buf[BUFSIZE];
	time_t curr;

	fd = open(lockfile, O_RDONLY);

	if (fd >= 0) {
		/* Lock exists, see who owns it */
		len = read(fd, buf, sizeof(buf));
		if (len > 0) {
			buf[len] = 0; /* Ensure null terminated string */
			pid = atoi(buf);
			if (!pid_exists(pid)) {
				/* Stale lock detected unlink and retry now */
				close(fd);
				unlink(lockfile);
				return 0;
			} else if (pid != 0) {
				/* Lock is held by an active pid, delay */
				close(fd);
				return 1;
			}
			/*
			 * If we reach this point, the PID was 0 which is
			 * unexpected.  Proceed under the assumption that the
			 * proper PID hasn't been written yet.
			 */
		}
		/*
		 * PID hasn't been written yet?  Either a bad lock or a very
		 * new one.
		 */
		time(&curr);
		rc = fstat(fd, &info);
		close(fd);
		if (rc != 0) {
			/* Can't read file anymore, retry now */
			return 0;
		}
		if (curr > info.st_mtime + WAITPID) {
			/*
			 * PID should be in the file within 2 minutes,
			 * something went wrong.  Treat as stale.
			 */
			unlink(lockfile);
			return 0;
		}
		/* Otherwise, assume file was newly created and delay */
		return 1;
	}

	/* Couldn't open, try again immediately */
	return 0;
}

/**
 * Attempt to create a lockfile at the specified path.
 *
 * @param[in]      lockfile   Path to the lock file
 * @param[in]      retries    Number of times to retry if lock fails initially
 * @param[in]      pid        PID to use for lock ownership
 *
 * @retval         0          Lock created with PID as owner
 * @retval         !=0        Lock was not created
 */
static int do_lockfile_lock(char *lockfile, unsigned int retries, int pid)
{
	int fd, plen, len, rc = 0, snooze = 0;
	unsigned int tries = retries + 1;
	char buf[BUFSIZE];
	char *tpath;

	if (!lockfile)
		return UTIL_LOCKFILE_ERR;

	plen = snprintf(buf, sizeof(buf), "%d\n", pid);
	if (plen < 0 || (plen > ((int)sizeof(buf) - 1)))
		return UTIL_LOCKFILE_ERR;

	/* Allocate temporary lock file with a sufficiently unique path */
	len = util_asprintf(&tpath, "%s%05d%02x", lockfile, getpid(),
			    (unsigned int)time(NULL) & 255);
	if (len < 0)
		return UTIL_LOCKFILE_ERR;

	/* Open the temporary lockfile, write the specified pid */
	fd = open(tpath, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd < 0) {
		rc = UTIL_LOCKFILE_ERR;
		goto out;
	}

	len = write(fd, buf, plen);
	if (close(fd) != 0) {
		rc = UTIL_LOCKFILE_ERR;
		goto cleanup;
	}
	if (len != plen) {
		/* Failed to write the temp lockfile, bail out */
		rc = UTIL_LOCKFILE_ERR;
		goto cleanup;
	}

	/* Link the temprorary file to the real path */
	do {
		rc = link(tpath, lockfile);
		if (rc == 0) {
			/* Lock successfully acquired */
			rc = UTIL_LOCKFILE_OK;
			goto cleanup;
		}
		/* Lock already held - check for stale lock */
		rc = handle_stale_lock(lockfile);
		/* Only wait if the lock was not stale */
		if (rc != 0) {
			tries--;
			if (tries > 0) {
				snooze += WAITINC;
				snooze = (snooze > MAXWAIT) ? MAXWAIT : snooze;
				sleep(snooze);
			}
		}
	} while (tries > 0);

	/* Exhausted specified number of retries, exit on failure */
	rc = UTIL_LOCKFILE_LOCK_FAIL;

cleanup:
	unlink(tpath);
	free(tpath);
out:
	return rc;
}

/**
 * Attempt to release a lockfile at the specified path.
 *
 * @param[in]      lockfile   Path to the lock file
 * @param[in]      pid        PID that should own the lock
 *
 * @retval         0          Lock released
 * @retval         !=0        Lock was not released or did not exist
 */
static int do_lockfile_release(char *lockfile, int pid)
{
	int fd, len, lpid;
	char buf[BUFSIZE];

	if (!lockfile)
		return UTIL_LOCKFILE_ERR;

	/* Open lockfile, read the owning pid if it exists */
	fd = open(lockfile, O_RDONLY);
	if (fd < 0)
		return UTIL_LOCKFILE_RELEASE_NONE;
	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len <= 0)
		return UTIL_LOCKFILE_RELEASE_FAIL;
	buf[len] = 0;
	lpid = atoi(buf);

	/* Only release the lock if its held by the right pid */
	if (pid != lpid)
		return UTIL_LOCKFILE_RELEASE_FAIL;

	unlink(lockfile);

	return 0;
}

/**
 * Attempt to create a lockfile owned by this process at the specified path.
 *
 * @param[in]      lockfile   Path to the lock file
 * @param[in]      retries    Number of times to retry if lock fails initially
 *
 * @retval         0          Lock created
 * @retval         !=0        Lock was not created
 */
int util_lockfile_lock(char *lockfile, int retries)
{
	return do_lockfile_lock(lockfile, retries, getpid());
}

/**
 * Attempt to create a lockfile owned by the parent of this process at the
 * specified path.
 *
 * @param[in]      lockfile   Path to the lock file
 * @param[in]      retries    Number of times to retry if lock fails initially
 *
 * @retval         0          Lock created
 * @retval         !=0        Lock was not created
 */
int util_lockfile_parent_lock(char *lockfile, int retries)
{
	return do_lockfile_lock(lockfile, retries, getppid());
}

/**
 * Attempt to release a lockfile owned by this process at the specified path.
 *
 * @param[in]      lockfile   Path to the lock file
 *
 * @retval         0          Lock released
 * @retval         !=0        Lock was not released or did not exist
 */
int util_lockfile_release(char *lockfile)
{
	return do_lockfile_release(lockfile, getpid());
}

/**
 * Attempt to release a lockfile owned by the parent of this process at the
 * specified path.
 *
 * @param[in]      lockfile   Path to the lock file
 *
 * @retval         0          Lock released
 * @retval         !=0        Lock was not released or did not exist
 */
int util_lockfile_parent_release(char *lockfile)
{
	return do_lockfile_release(lockfile, getppid());
}
