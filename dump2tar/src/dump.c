/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Main dump logic
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include "buffer.h"
#include "dref.h"
#include "dump.h"
#include "global.h"
#include "idcache.h"
#include "misc.h"
#include "tar.h"

/* Default input file read size (bytes) */
#define DEFAULT_READ_CHUNK_SIZE		(512 * 1024)
#define DEFAULT_MAX_BUFFER_SIZE		(2 * 1024 * 1024)

#define _SET_ABORTED(task)	_set_aborted((task), __func__, __LINE__)
#define SET_ABORTED(task)	set_aborted((task), __func__, __LINE__)

#define read_error(task, filename, fmt, ...) \
	do { \
		if (!(task)->opts->ignore_failed_read) \
			SET_ABORTED((task)); \
		_mwarn(true, "%s: " fmt, (filename), ##__VA_ARGS__); \
	} while (0)

#define write_error(task, fmt, ...) \
	do { \
		SET_ABORTED((task)); \
		_mwarn(true, "%s: " fmt, (task)->opts->output_file, \
		      ##__VA_ARGS__); \
	} while (0)

#define tverb(fmt, ...)	\
	do { \
		if (task->opts->verbose) \
			verb((fmt), ##__VA_ARGS__); \
	} while (0)


/* Jobs representing a file or command output to add */
struct job {
	struct job *next_job;
	enum job_type {
		JOB_INIT,	/* Initialization work */
		JOB_FILE,	/* Add a regular file */
		JOB_LINK,	/* Add a symbolic link */
		JOB_DIR,	/* Add a directory */
		JOB_CMD,	/* Add command output */
	} type;
	enum job_status {
		JOB_QUEUED,	/* Transient: Job processing has not started */
		JOB_IN_PROGRESS,/* Transient: Job processing has started */
		JOB_EXCLUDED,	/* Final: File was excluded */
		JOB_FAILED,	/* Final: Data could not be obtained */
		JOB_DONE,	/* Final: All data was obtained */
		JOB_PARTIAL,	/* Final: Only some data was obtained */
	} status;
	char *outname;
	char *inname;
	char *relname;
	struct stat stat;
	bool timed;
	struct timespec deadline;
	struct dref *dref;
	int cmd_status;
	struct buffer *content;
};

/* Run-time statistics */
struct stats {
	unsigned long num_done;
	unsigned long num_excluded;
	unsigned long num_failed;
	unsigned long num_partial;
};

/* Information specific to a single dump task */
struct task {
	/* Input */
	struct dump_opts *opts;

	/* State */

	/* mutex serializes access to global data */
	pthread_mutex_t mutex;
	pthread_cond_t worker_cond;
	pthread_cond_t cond;
	unsigned long num_jobs_active;
	struct job *jobs_head;
	struct job *jobs_tail;
	bool aborted;

	/* output_mutex serializes access to output file */
	pthread_mutex_t output_mutex;
	int output_fd;
	size_t output_written;
#ifdef HAVE_ZLIB
	gzFile output_gzfd;
#endif /* HAVE_ZLIB */
	unsigned long output_num_files;

	/* No protection needed (only accessed in single-threaded mode) */
	struct stats stats;
	struct timespec start_ts;
};

/* Per thread management data */
struct per_thread {
	long num;
	pthread_t thread;
	bool running;
	bool timed_out;
	struct stats stats;
	struct job *job;
	struct buffer buffer;
	struct task *task;
};

static const struct {
	mode_t mode;
	char c;
} exclude_types[NUM_EXCLUDE_TYPES] = {
	{ S_IFREG, 'f' },
	{ S_IFDIR, 'd' },
	{ S_IFCHR, 'c' },
	{ S_IFBLK, 'b' },
	{ S_IFIFO, 'p' },
	{ S_IFLNK, 'l' },
	{ S_IFSOCK, 's' },
};

/* Lock main mutex */
static void main_lock(struct task *task)
{
	if (!global_threaded)
		return;
	DBG("main lock");
	pthread_mutex_lock(&task->mutex);
}

/* Unlock main mutex */
static void main_unlock(struct task *task)
{
	if (!global_threaded)
		return;
	DBG("main unlock");
	pthread_mutex_unlock(&task->mutex);
}

/* Lock output mutex */
static void output_lock(struct task *task)
{
	if (!global_threaded)
		return;
	pthread_mutex_lock(&task->output_mutex);
}

/* Unlock output mutex */
static void output_unlock(struct task *task)
{
	if (!global_threaded)
		return;
	pthread_mutex_unlock(&task->output_mutex);
}

/* Wake up all waiting workers */
static void _worker_wakeup_all(struct task *task)
{
	if (!global_threaded)
		return;
	DBG("waking up all worker threads");
	pthread_cond_broadcast(&task->worker_cond);
}

/* Wake up one waiting worker */
static void _worker_wakeup_one(struct task *task)
{
	if (!global_threaded)
		return;
	DBG("waking up one worker thread");
	pthread_cond_signal(&task->worker_cond);
}

/* Wait for a signal to a worker */
static int _worker_wait(struct task *task)
{
	int rc;

	DBG("waiting for signal to worker");
	rc = pthread_cond_wait(&task->worker_cond, &task->mutex);
	DBG("waiting for signal to worker done (rc=%d)", rc);

	return rc;
}

/* Wake up main thread */
static void _main_wakeup(struct task *task)
{
	if (!global_threaded)
		return;
	DBG("waking up main thread");
	pthread_cond_broadcast(&task->cond);
}

/* Wait for a signal to the main thread */
static int _main_wait(struct task *task)
{
	int rc;

	DBG("waiting for status change");
	rc = pthread_cond_wait(&task->cond, &task->mutex);
	DBG("waiting for status change done (rc=%d)", rc);

	return rc;
}

/* Wait for a signal to the main thread. Abort waiting after @deadline */
static int _main_wait_timed(struct task *task, struct timespec *deadline)
{
	int rc;

	DBG("timed waiting for status change");
	rc = pthread_cond_timedwait(&task->cond, &task->mutex, deadline);
	DBG("timed waiting for status change done (rc=%d)", rc);

	return rc;
}

/* Allow thread to be canceled */
static void cancel_enable(void)
{
	if (!global_threaded)
		return;
	if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0)
		mwarn("pthread_setcancelstate");
}

/* Prevent thread from being canceled */
static void cancel_disable(void)
{
	if (!global_threaded)
		return;
	if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0)
		mwarn("pthread_setcancelstate");
}

/* Abort processing and inform all threads to shutdown. Must be called with
 * task->mutex locked */
static void _set_aborted(struct task *task, const char *func, unsigned int line)
{
	DBG("set aborted at %s:%u", func, line);
	task->aborted = true;
	_worker_wakeup_all(task);
	_main_wakeup(task);
}

/* Abort processing and inform all threads to shutdown */
static void set_aborted(struct task *task, const char *func, unsigned int line)
{
	main_lock(task);
	_set_aborted(task, func, line);
	main_unlock(task);
}

/* Check if abort processing has been initiated */
static bool is_aborted(struct task *task)
{
	bool result;

	main_lock(task);
	result = task->aborted;
	main_unlock(task);

	return result;
}

/* Release resources associated with @job */
static void free_job(struct task *task, struct job *job)
{
	DBG("free job %p (%s)", job, job->inname);
	if (!job)
		return;
	free(job->inname);
	free(job->outname);
	free(job->relname);
	dref_put(job->dref);
	free(job);
}

/* Check if file type specified by mode @m was marked as excluded */
static bool is_type_excluded(struct dump_opts *opts, mode_t m)
{
	int i;

	m &= S_IFMT;
	for (i = 0; i < NUM_EXCLUDE_TYPES; i++) {
		if (exclude_types[i].mode == m)
			return opts->exclude_type[i];
	}
	return false;
}

/* Replace all '/' characters in @filename with '_' */
static void escape_filename(char *filename)
{
	for (; *filename; filename++) {
		if (*filename == '/')
			*filename = '_';
	}
}

/* Determine filename in archive from original filename @inname and
 * requested new filename @outname and depending on @type. */
static void set_outname(char **result_ptr, const char *outname,
			const char *inname, enum job_type type)
{
	const char *prefix = "", *name, *suffix;
	char *result, *end;
	size_t olen = outname ? strlen(outname) : 0, plen, nlen;

	if (olen == 0) {
		/* No output name specified: outname = inname */
		name = inname;
	} else if (outname[olen - 1] == '/') {
		/* Output name is a directory: outname = outname/inname */
		prefix = outname;
		name = inname;
	} else {
		/* Output name is a filename: outname = inname */
		name = outname;
	}

	if (type == JOB_DIR)
		suffix = "/";
	else
		suffix = "";

	plen = strlen(prefix);
	nlen = strlen(name);

	result = mmalloc(plen + nlen + strlen(suffix) + /* NUL */ 1);

	/* Add prefix */
	strcpy(result, prefix);

	/* Add name */
	end = result + plen;
	strcpy(end, name);
	if (type == JOB_CMD)
		escape_filename(end);

	/* Add suffix */
	end = end + nlen;
	strcpy(end, suffix);

	remove_double_slashes(result);

	*result_ptr = result;
}

static void sanitize_dirname(char **name_ptr)
{
	char *name;

	name = mmalloc(strlen(*name_ptr) + /* Slash */ 1 + /* NUL */ 1);
	strcpy(name, *name_ptr);
	remove_double_slashes(name);
	chomp(name, "/");
	strcat(name, "/");
	free(*name_ptr);
	*name_ptr = name;
}

/* Allocate and initialize a new job representation to add an entry according
 * to the specified parameters. @relname and @dref are used for opening files
 * more efficiently using *at() functions if specified. @is_cmd specifies if
 * the specified inname is a command line. */
static struct job *create_job(struct task *task, const char *inname,
			      const char *outname, bool is_cmd,
			      const char *relname, struct dref *dref,
			      struct stats *stats)
{
	struct job *job = mmalloc(sizeof(struct job));
	int rc;

	DBG("create job inname=%s outname=%s is_cmd=%d relname=%s dref=%p",
	    inname, outname, is_cmd, relname, dref);

	job->status = JOB_QUEUED;

	if (!inname) {
		job->type = JOB_INIT;
		return job;
	}

	job->inname = mstrdup(inname);

	if (is_cmd) {
		/* Special case - read from command output */
		job->type = JOB_CMD;
		set_dummy_stat(&job->stat);
		goto out;
	}

	if (!relname && strcmp(job->inname, "-") == 0) {
		/* Special case - read from standard input */
		job->type = JOB_FILE;
		set_dummy_stat(&job->stat);
		goto out;
	}

	rc = stat_file(task->opts->dereference, job->inname, relname, dref,
		       &job->stat);

	if (rc < 0) {
		read_error(task, job->inname, "Cannot stat file");
		free_job(task, job);
		stats->num_failed++;
		return NULL;
	}

	if (is_type_excluded(task->opts, job->stat.st_mode)) {
		free_job(task, job);
		stats->num_excluded++;
		return NULL;
	}

	if (S_ISLNK(job->stat.st_mode)) {
		job->type = JOB_LINK;
	} else if (S_ISDIR(job->stat.st_mode)) {
		job->type = JOB_DIR;
		sanitize_dirname(&job->inname);

		/* No need to keep parent directory open */
		relname = NULL;
		dref = NULL;
	} else {
		job->type = JOB_FILE;
	}

	if (relname)
		job->relname = mstrdup(relname);
	job->dref = dref_get(dref);

out:
	set_outname(&job->outname, outname, inname, job->type);

	return job;
}

void job_print(struct job *job)
{
	printf("DEBUG: job_print at %p\n", job);
	printf("DEBUG:   next_job=%p\n", job->next_job);
	printf("DEBUG:   type=%d\n", job->type);
	printf("DEBUG:   status==%d\n", job->status);
	printf("DEBUG:   outname=%s\n", job->outname);
	printf("DEBUG:   inname=%s\n", job->inname);
	printf("DEBUG:   relname=%s\n", job->relname);
	printf("DEBUG:   timed=%d\n", job->timed);
	printf("DEBUG:   dref=%p\n", job->dref);
	printf("DEBUG:   cmd_status=%d\n", job->cmd_status);
	printf("DEBUG:   content=%p\n", job->content);
}

/* Return the number of bytes written to the output file */
static size_t get_output_size(struct task *task)
{
#ifdef HAVE_ZLIB
	if (task->opts->gzip) {
		gzflush(task->output_gzfd, Z_SYNC_FLUSH);
		return gztell(task->output_gzfd);
	}
#endif /* HAVE_ZLIB */
	return task->output_written;
}

/* Write @len bytes at address @ptr to the output file */
static int write_output(struct task *task, const char *ptr, size_t len)
{
	size_t todo = len;
	ssize_t w;

#ifdef HAVE_ZLIB
	if (task->opts->gzip) {
		if (gzwrite(task->output_gzfd, ptr, len) == 0)
			goto err_write;
		task->output_written += len;

		return EXIT_OK;
	}
#endif /* HAVE_ZLIB */

	while (todo > 0) {
		w = write(task->output_fd, ptr, todo);
		if (w < 0)
			goto err_write;
		todo -= w;
		ptr += w;
	}
	task->output_written += len;

	return EXIT_OK;

err_write:
	write_error(task, "Cannot write output");

	return EXIT_RUNTIME;
}

/* Write an end-of-file marker to the output file */
static void write_eof(struct task *task)
{
	char zeroes[TAR_BLOCKSIZE];

	memset(zeroes, 0, sizeof(zeroes));
	write_output(task, zeroes, TAR_BLOCKSIZE);
	write_output(task, zeroes, TAR_BLOCKSIZE);
}

/* Callback for writing out chunks of job data */
static int _write_job_data_cb(void *data, void *addr, size_t len)
{
	struct task *task = data;

	return write_output(task, addr, len);
}

/* Write tar entry for a file containing the exit status of the process that
 * ran command job @job */
static int write_job_status_file(struct task *task, struct job *job)
{
	char *name, *content;
	size_t len;
	struct stat st;
	int rc, status = job->cmd_status, exitstatus = -1, termsig = -1,
	    waitpid_errno = -1;

	name = masprintf("%s.cmdstatus", job->outname);
	if (status < 0)
		waitpid_errno = -status;
	else if (WIFEXITED(status))
		exitstatus = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		termsig = WTERMSIG(status);

	content = masprintf("EXITSTATUS=%d\n"
			    "TERMSIG=%d\n"
			    "WAITPID_ERRNO=%d\n", exitstatus, termsig,
			    waitpid_errno);

	len = strlen(content);
	set_dummy_stat(&st);
	rc = tar_emit_file_from_data(name, NULL, len, &st, TYPE_REGULAR,
				     content, _write_job_data_cb, task);
	free(name);
	free(content);

	return rc;
}

/* Write tar entry for data in @job to output. Must be called with output_lock
 * held. */
static void _write_job_data(struct task *task, struct job *job)
{
	struct buffer *buffer = job->content;

	switch (job->status) {
	case JOB_DONE:
	case JOB_PARTIAL:
		break;
	case JOB_FAILED:
		/* Create empty entries for failed reads */
		if (task->opts->ignore_failed_read)
			break;
		return;
	default:
		return;
	}

	switch (job->type) {
	case JOB_CMD:
		tar_emit_file_from_buffer(job->outname, NULL, buffer->total,
					  &job->stat, TYPE_REGULAR, buffer,
					  _write_job_data_cb, task);
		task->output_num_files++;
		if (task->opts->add_cmd_status) {
			write_job_status_file(task, job);
			task->output_num_files++;
		}
		break;
	case JOB_FILE:
		tar_emit_file_from_buffer(job->outname, NULL, buffer->total,
					  &job->stat, TYPE_REGULAR, buffer,
					  _write_job_data_cb, task);
		task->output_num_files++;
		break;
	case JOB_LINK:
		tar_emit_file_from_buffer(job->outname, buffer->addr, 0,
					  &job->stat, TYPE_LINK, NULL,
					  _write_job_data_cb, task);
		task->output_num_files++;
		break;
	case JOB_DIR:
		tar_emit_file_from_buffer(job->outname, NULL, 0, &job->stat,
					  TYPE_DIR, NULL, _write_job_data_cb,
					  task);
		task->output_num_files++;
		break;
	default:
		break;
	}

	if (task->opts->max_size > 0 &&
	    get_output_size(task) > task->opts->max_size) {
		mwarnx("Archive size exceeds maximum of %ld bytes - aborting",
		      task->opts->max_size);
		SET_ABORTED(task);
	}
}

/* Read the contents of the symbolic link at @filename. On success, the
 * contents is returned in @buffer and the return value is %EXIT_OK.
 * If @relname is non-null it points to the name of the file relative
 * to its parent directory for which @dirfd is an open file handle. */
static int read_symlink(struct task *task, const char *filename,
			const char *relname, int dirfd, struct buffer *buffer)
{
	ssize_t actual = 0;
	size_t currlen = buffer->size ? buffer->size :
					task->opts->read_chunk_size;
	int rc = EXIT_OK;

	while (!is_aborted(task)) {
		buffer_make_room(buffer, currlen, false,
				 task->opts->max_buffer_size);

		cancel_enable();
		if (relname)
			actual = readlinkat(dirfd, relname, buffer->addr,
					    buffer->size);
		else
			actual = readlink(filename, buffer->addr, buffer->size);
		cancel_disable();

		if (actual == -1) {
			read_error(task, filename, "Cannot read link");
			rc = EXIT_RUNTIME;
			/* Reset actual counter to get an empty buffer */
			actual = 0;
			break;
		}

		/* Ensure that content doesn't exceed --file-max-size limit */
		if (task->opts->file_max_size > 0 &&
		    (size_t) actual > task->opts->file_max_size) {
			actual = task->opts->file_max_size;/* Don't count NUL */
			mwarnx("%s: Warning: Data exceeds maximum size of %ld "
			      "bytes - truncating", filename,
			      task->opts->file_max_size);
			break;
		}

		if ((size_t) actual < buffer->size)
			break;

		currlen += task->opts->read_chunk_size;
	}

	if (rc == EXIT_OK && is_aborted(task))
		rc = EXIT_RUNTIME;

	buffer->addr[actual] = 0;
	buffer->total = actual + 1;

	return rc;
}

/* Read data from the file descriptor @fd until an end-of-file condition is
 * encountered. On success, *@done bytes in @buffer contain the read data
 * and the return value is %EXIT_OK. */
static int read_fd(struct task *task, const char *name, int fd,
		   struct buffer *buffer)
{
	ssize_t rc = 0;
	size_t c = buffer->size ? buffer->size : task->opts->read_chunk_size;

	while (!is_aborted(task)) {
		cancel_enable();
		rc = buffer_read_fd(buffer, fd, c, true,
				    task->opts->max_buffer_size);
		cancel_disable();

		if (rc <= 0)
			break;

		/* Ensure that content doesn't exceed --file-max-size limit */
		if (task->opts->file_max_size > 0 &&
		    buffer->total >= task->opts->file_max_size) {
			buffer_truncate(buffer, task->opts->file_max_size);
			rc = 0;
			mwarnx("%s: Warning: Data exceeds maximum size of %ld "
			      "bytes - truncating", name,
			      task->opts->file_max_size);
			break;
		}

		c = buffer->size - buffer->off;
		if (c > 0) {
			/* Read to memory */
		} else if (buffer->size + task->opts->read_chunk_size <
			   task->opts->max_buffer_size) {
			/* Enlarge memory buffer */
			c = task->opts->read_chunk_size;
		} else {
			/* Use full memory buffer size */
			c = task->opts->max_buffer_size;
		}
	}

	if (is_aborted(task) || rc != 0)
		return EXIT_RUNTIME;

	return EXIT_OK;
}

/* Read data from the file at @filename until an end-of-file condition is
 * encountered. On success, @buffer contains the data read and the return
 * value is %EXIT_OK. If @relname is non-null it points to the name of the
 * file relative to its parent directory for which @dirfd is an open file
 * handle. */
static int read_regular(struct task *task, const char *filename,
			const char *relname, int dirfd, struct buffer *buffer)
{
	int fd, rc = EXIT_OK;
	bool need_close = true;

	/* Opening a named pipe can block when peer is not ready */
	cancel_enable();
	if (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		need_close = false;
		filename = "Standard input";
	} else if (relname)
		fd = openat(dirfd, relname, O_RDONLY);
	else
		fd = open(filename, O_RDONLY);
	cancel_disable();

	if (fd < 0) {
		read_error(task, filename, "Cannot open file");
		return EXIT_RUNTIME;
	}

	rc = read_fd(task, filename, fd, buffer);
	if (rc) {
		if (is_aborted(task))
			mwarnx("%s: Read aborted", filename);
		else
			read_error(task, filename, "Cannot read file");
	}

	if (need_close)
		close(fd);

	return rc;
}

/* Read the output of command @cmd until an end-of-file condition is
 * encountered. On success, @buffer contain the output and the return value
 * is %EXIT_OK. When not %NULL, use @status_ptr to store the resulting process
 * status. */
static int read_cmd_output(struct task *task, char *cmd, struct buffer *buffer,
			   int *status_ptr)
{
	int fd, rc = EXIT_RUNTIME;
	pid_t pid;

	fd = cmd_open(cmd, &pid);
	if (fd < 0) {
		read_error(task, cmd, "Cannot run command");
		return rc;
	}

	if (read_fd(task, cmd, fd, buffer)) {
		if (is_aborted(task))
			mwarnx("%s: Command aborted", cmd);
		else
			read_error(task, cmd, "Cannot read command output");
	} else
		rc = EXIT_OK;

	cmd_close(fd, pid, status_ptr);

	return rc;

}

/* Check the exclude patterns in @task->opts->exclude for a match of @filename.
 * If found, return the matching pattern string, otherwise return %NULL. */
static const char *get_exclude_match(struct task *task, const char *filename)
{
	unsigned int i;
	int mode = FNM_PERIOD | FNM_NOESCAPE;

	for (i = 0; i < task->opts->exclude.num; i++) {
		if (fnmatch(task->opts->exclude.str[i], filename, mode) == 0)
			return task->opts->exclude.str[i];
	}

	return NULL;
}

/* Add the specified @job to the start of the job queue */
static void _queue_job_head(struct task *task, struct job *job)
{
	DBG("queue job type=%d inname=%s at head", job->type, job->inname);
	job->next_job = task->jobs_head;
	task->jobs_head = job;
	if (!task->jobs_tail)
		task->jobs_tail = job;
}

/* Add the specified @job to the end of the job queue */
static void _queue_job_tail(struct task *task, struct job *job)
{
	DBG("queue job type=%d inname=%s at tail", job->type, job->inname);
	if (task->jobs_tail)
		task->jobs_tail->next_job = job;
	else
		task->jobs_head = job;
	task->jobs_tail = job;
}

/* Add the specified @job to the job queue and trigger processing.
 * If @head is %true, the new job is inserted at the start of the job queue,
 * otherwise at the end. */
static void queue_job(struct task *task, struct job *job, bool head)
{
	main_lock(task);
	task->num_jobs_active++;
	if (head)
		_queue_job_head(task, job);
	else
		_queue_job_tail(task, job);
	_worker_wakeup_one(task);
	main_unlock(task);
}

/* Add the specified list of jobs starting with @first up to @last to the start
 * of the job queue and trigger processing */
static void queue_jobs(struct task *task, struct job *first, struct job *last,
		       int num)
{
	main_lock(task);
	last->next_job = task->jobs_head;
	task->jobs_head = first;
	task->num_jobs_active += num;
	_worker_wakeup_all(task);
	main_unlock(task);
}

/* Remove the head of the job queue and return it to the caller */
static struct job *_dequeue_job(struct task *task)
{
	struct job *job = NULL;

	if (task->jobs_head) {
		job = task->jobs_head;
		task->jobs_head = job->next_job;
		job->next_job = NULL;
		if (job == task->jobs_tail)
			task->jobs_tail = NULL;
		DBG("dequeueing job type=%d inname=%s", job->type, job->inname);
		job->status = JOB_IN_PROGRESS;
	} else {
		DBG("no job to dequeue");
	}

	return job;
}

/* Create and queue job for file at @filename */
static void queue_file(struct task *task, const char *inname,
		       const char *outname, bool is_cmd,
		       const char *relname, struct dref *dref,
		       struct stats *stats, bool head)
{
	struct job *job;

	job = create_job(task, inname, outname, is_cmd, relname, dref, stats);
	if (job)
		queue_job(task, job, head);
}

/* Queue initial job */
static void init_queue(struct task *task)
{
	queue_file(task, NULL, NULL, false, NULL, NULL, NULL, true);
}

/* Create and queue jobs for all files found in @dirname */
static void queue_dir(struct task *task, const char *dirname,
		      const char *outname, struct stats *stats)
{
	struct dirent *de;
	char *inpath, *outpath;
	struct dref *dref;
	struct job *job, *first = NULL, *last = NULL;
	int num = 0;

	dref = dref_create(dirname);
	if (!dref) {
		read_error(task, dirname, "Cannot read directory");
		return;
	}

	while ((de = readdir(dref->dd))) {
		if (de->d_name[0] == '.') {
			if (de->d_name[1] == 0)
				continue;
			if (de->d_name[1] == '.' && de->d_name[2] == 0)
				continue;
		}
		DBG("next file %s", de->d_name);
		inpath = masprintf("%s%s", dirname, de->d_name);
		outpath = masprintf("%s%s", outname, de->d_name);
		job = create_job(task, inpath, outpath, false, de->d_name, dref,
				 stats);
		if (job) {
			if (last) {
				last->next_job = job;
				last = job;
			} else {
				first = job;
				last = job;
			}
			num++;
		}
		free(inpath);
		free(outpath);
	}

	if (first)
		queue_jobs(task, first, last, num);

	dref_put(dref);
}

/* Create and queue jobs for all files specified on the command line */
static void queue_jobs_from_opts(struct task *task, struct stats *stats)
{
	struct dump_opts *opts = task->opts;
	unsigned int i;

	/* Queue directly specified entries */
	for (i = 0; i < opts->num_specs && !is_aborted(task); i++) {
		queue_file(task, opts->specs[i].inname, opts->specs[i].outname,
			   opts->specs[i].is_cmd, NULL, NULL, stats, false);
	}
}

/* Prepare output stream */
static int open_output(struct task *task)
{
	bool to_stdout = !task->opts->output_file ||
			 strcmp(task->opts->output_file, "-") == 0;
	int rc = EXIT_OK;
	struct stat st;

	if (to_stdout) {
		set_stdout_data();
		task->opts->output_file = "Standard output";
	}

	cancel_enable();
#ifdef HAVE_ZLIB
	if (task->opts->gzip) {
		if (to_stdout) {
			task->output_gzfd =
				gzdopen(STDOUT_FILENO,
					task->opts->append ? "ab" : "wb");
		} else {
			task->output_gzfd =
				gzopen(task->opts->output_file,
				       task->opts->append ? "ab" : "wb");
		}

		if (!task->output_gzfd)
			rc = EXIT_RUNTIME;
		goto out;
	}
#endif /* HAVE_ZLIB */

	if (to_stdout) {
		task->output_fd = STDOUT_FILENO;
	} else {
		task->output_fd =
			open(task->opts->output_file, O_WRONLY | O_CREAT |
			     (task->opts->append ? O_APPEND : 0), 0666);
	}

	if (task->output_fd < 0)
		rc = EXIT_RUNTIME;
	else if (!task->opts->append) {
		if (fstat(task->output_fd, &st) == -1)
			rc = EXIT_RUNTIME;
		else if (S_ISREG(st.st_mode) &&
			 ftruncate(task->output_fd, 0) == -1)
			rc = EXIT_RUNTIME;
	}

#ifdef HAVE_ZLIB
out:
#endif /* HAVE_ZLIB */
	cancel_disable();

	if (rc != EXIT_OK) {
		mwarn("%s: Cannot open output file", task->opts->output_file);
		return rc;
	}

	return EXIT_OK;
}

/* Determine if the specified @job should be excluded from archiving */
static bool is_job_excluded(struct task *task, struct job *job)
{
	const char *pat;

	if (job->type == JOB_INIT || job->type == JOB_CMD)
		return false;

	pat = get_exclude_match(task, job->inname);
	if (!pat)
		return false;

	tverb("Excluding '%s' due to exclude pattern '%s'\n", job->inname, pat);

	return true;
}

/* Perform all actions necessary to process @job and add resulting tar
 * data buffers to the buffer list of @thread. */
static void process_job(struct per_thread *thread, struct job *job)
{
	struct task *task = thread->task;
	const char *relname = job->dref ? job->relname : NULL;
	int dirfd = job->dref ? job->dref->dirfd : -1;
	struct buffer *buffer = &thread->buffer;
	enum job_status status = JOB_DONE;

	DBG("processing job type=%d inname=%s", job->type, job->inname);

	if (is_job_excluded(task, job)) {
		status = JOB_EXCLUDED;
		goto out;
	}

	switch (job->type) {
	case JOB_INIT: /* Perform initial setup steps */
		if (open_output(task)) {
			SET_ABORTED(task);
			status = JOB_FAILED;
			goto out;
		}
		queue_jobs_from_opts(task, &thread->stats);
		break;
	case JOB_CMD: /* Capture command output */
		tverb("Dumping command output '%s'\n", job->inname);

		set_dummy_stat(&job->stat);
		if (read_cmd_output(task, job->inname, buffer,
				    &job->cmd_status))
			status = JOB_FAILED;

		break;
	case JOB_LINK: /* Read symbolic link */
		tverb("Dumping link '%s'\n", job->inname);

		if (read_symlink(task, job->inname, relname, dirfd, buffer))
			status = JOB_FAILED;

		break;
	case JOB_DIR: /* Read directory contents */
		tverb("Dumping directory '%s'\n", job->inname);

		if (task->opts->recursive) {
			queue_dir(task, job->inname, job->outname,
				  &thread->stats);
		}
		break;
	case JOB_FILE: /* Read file contents */
		tverb("Dumping file '%s'\n", job->inname);

		if (read_regular(task, job->inname, relname, dirfd, buffer))
			status = JOB_FAILED;

		break;
	default:
		break;
	}

out:
	job->status = status;
	DBG("processing done status=%d", job->status);
}

/* Add @job results to statistics @stats */
static void account_stats(struct task *task, struct stats *stats,
			  struct job *job)
{
	DBG("accounting job %s", job->inname);

	if (job->type == JOB_INIT)
		return;

	switch (job->status) {
	case JOB_DONE:
		stats->num_done++;
		if (job->type == JOB_CMD && task->opts->add_cmd_status)
			stats->num_done++;
		break;
	case JOB_PARTIAL:
		stats->num_done++;
		stats->num_partial++;
		if (job->type == JOB_CMD && task->opts->add_cmd_status)
			stats->num_done++;
		break;
	case JOB_FAILED:
		stats->num_failed++;
		break;
	case JOB_EXCLUDED:
		stats->num_excluded++;
		break;
	default:
		break;
	}
}

/* Add statistics @from to @to */
static void add_stats(struct stats *to, struct stats *from)
{
	to->num_done += from->num_done;
	to->num_partial += from->num_partial;
	to->num_excluded += from->num_excluded;
	to->num_failed += from->num_failed;
}

/* Release resources allocated to @thread */
static void cleanup_thread(struct per_thread *thread)
{
	if (thread->job)
		free_job(thread->task, thread->job);
	buffer_free(&thread->buffer, false);
}

/* Register activate @job at @thread */
static void start_thread_job(struct per_thread *thread, struct job *job)
{
	struct task *task = thread->task;

	thread->job = job;
	job->content = &thread->buffer;
	if (task->opts->file_timeout > 0 && job->type != JOB_INIT) {
		/* Set up per-job timeout */
		set_timespec(&job->deadline, task->opts->file_timeout, 0);
		job->timed = true;

		/* Signal main thread to update deadline timeout */
		_main_wakeup(task);
	}
}

/* Unregister active @job at @thread */
static void stop_thread_job(struct per_thread *thread, struct job *job)
{
	thread->job = NULL;
	job->content = NULL;
	buffer_reset(&thread->buffer);
}

/* Wait until a job is available in the job queue. When a job becomes
 * available, dequeue and return it. Return %NULL if no more jobs are
 * available, or if processing was aborted. Must be called with task->mutex
 * locked. */
static struct job *_get_next_job(struct task *task)
{
	struct job *job = NULL;

	do {
		DBG("checking for jobs");
		if (task->aborted)
			break;
		job = _dequeue_job(task);
		if (job)
			break;
		if (task->num_jobs_active == 0)
			break;
		DBG("found no jobs (%d active)", task->num_jobs_active);
	} while (_worker_wait(task) == 0);

	return job;
}

/* Unlock the mutex specified by @data */
static void cleanup_unlock(void *data)
{
	pthread_mutex_t *mutex = data;

	pthread_mutex_unlock(mutex);
}

/* Write entry for data in @job to output */
static void write_job_data(struct task *task, struct job *job)
{
	DBG("write_job_data");
	output_lock(task);
	pthread_cleanup_push(cleanup_unlock, &task->output_mutex);
	cancel_enable();

	_write_job_data(task, job);

	cancel_disable();
	pthread_cleanup_pop(0);
	output_unlock(task);
}

/* Perform second part of job processing for @job at @thread by writing the
 * resulting tar file entry */
static void postprocess_job(struct per_thread *thread, struct job *job,
			    bool cancelable)
{
	struct task *task = thread->task;

	account_stats(task, &thread->stats, job);
	if (cancelable)
		write_job_data(task, job);
	else
		_write_job_data(task, job);
}

/* Mark @job as complete by releasing all associated resources. If this was
 * the last active job inform main thread. Must be called with main_lock
 * mutex held. */
static void _complete_job(struct task *task, struct job *job)
{
	task->num_jobs_active--;
	if (task->num_jobs_active == 0)
		_main_wakeup(task);
	free_job(task, job);
}

static void init_thread(struct per_thread *thread, struct task *task, long num)
{
	memset(thread, 0, sizeof(struct per_thread));
	thread->task = task;
	thread->num = num;
}

/* Dequeue and process all jobs on the job queue */
static int process_queue(struct task *task)
{
	struct job *job;
	struct per_thread thread;

	init_thread(&thread, task, 0);

	while ((job = _dequeue_job(task)) && !is_aborted(task)) {
		start_thread_job(&thread, job);
		process_job(&thread, job);
		postprocess_job(&thread, job, false);
		stop_thread_job(&thread, job);
		_complete_job(task, job);
	}

	task->stats = thread.stats;
	cleanup_thread(&thread);

	return EXIT_OK;
}

/* Return %true if @job is in a final state, %false otherwise */
static bool job_is_final(struct job *job)
{
	switch (job->status) {
	case JOB_DONE:
	case JOB_PARTIAL:
	case JOB_EXCLUDED:
	case JOB_FAILED:
		return true;
	default:
		break;
	}

	return false;
}

/* Main thread function: process jobs on the job queue until all jobs
 * are processed or processing was aborted. */
static void *worker_thread_main(void *d)
{
	struct per_thread *thread = d;
	struct task *task = thread->task;
	struct job *job;

	/* Allow cancel only at specific code points */
	cancel_disable();
	set_threadname("%*sworker %d", (thread->num + 1) * 2, "", thread->num);

	/* Handle jobs left over from canceled thread */
	job = thread->job;
	if (job) {
		DBG("handle aborted job %p", job);

		postprocess_job(thread, job, true);

		main_lock(task);
		if (thread->timed_out)
			goto out;
		stop_thread_job(thread, job);
		_complete_job(task, job);
		main_unlock(task);
	}

	DBG("enter worker loop");

	main_lock(task);
	while ((job = _get_next_job(task))) {
		start_thread_job(thread, job);
		main_unlock(task);

		process_job(thread, job);
		postprocess_job(thread, job, true);

		main_lock(task);
		if (thread->timed_out)
			goto out;
		stop_thread_job(thread, job);
		_complete_job(task, job);
	}

out:
	thread->running = false;
	_main_wakeup(task);
	main_unlock(task);

	cancel_enable();
	DBG("leave work loop");

	return NULL;
}

/* Start a worker thread associated with the specified @data. Return %EXIT_OK on
 * success. */
static int start_worker_thread(struct per_thread *data)
{
	int rc;

	DBG("start thread");
	global_threaded = true;
	data->timed_out = false;
	rc = pthread_create(&data->thread, NULL, &worker_thread_main, data);
	if (rc) {
		mwarnx("Cannot start thread: %s", strerror(rc));
		return EXIT_RUNTIME;
	}
	data->running = true;

	return EXIT_OK;
}

/* Perform timeout handling for thread associated with @data by canceling and
 * restarting the corresponding thread. Must be called with task->mutex
 * held. */
static void _timeout_thread(struct per_thread *data)
{
	struct task *task = data->task;
	struct job *job = data->job;
	pthread_t thread = data->thread;
	const char *op, *action;

	if (!job) {
		/* Timeout raced with job completion */
		return;
	}
	if (job_is_final(job)) {
		/* Job processing done, timeout does not apply */
		return;
	}

	data->timed_out = true;

	/* Allow thread to obtain main lock during cancel handling */
	main_unlock(task);
	DBG("cancel num=%d thread=%p", data->num, thread);
	pthread_cancel(thread);
	DBG("join num=%d thread=%p", data->num, thread);

	pthread_join(thread, NULL);
	main_lock(task);

	DBG("join done");

	if (job->type == JOB_CMD)
		op = "Command";
	else
		op = "Read";

	if (task->opts->ignore_failed_read)
		action = "skipping";
	else
		action = "aborting";

	if (!job->inname || !*job->inname)
		job_print(job);
	mwarnx("%s: %s%s timed out after %d second%s - %s", job->inname,
	      task->opts->ignore_failed_read ? "Warning: " : "", op,
	      task->opts->file_timeout,
	      task->opts->file_timeout > 1 ? "s" : "", action);
	if (!task->opts->ignore_failed_read)
		_SET_ABORTED(task);

	/* Interrupted job will be handled by new thread - adjust status */
	if (job->status == JOB_IN_PROGRESS)
		job->status = JOB_PARTIAL;
	else if (!job_is_final(job))
		job->status = JOB_FAILED;

	if (start_worker_thread(data))
		_SET_ABORTED(task);
}

/* Return the number of currently running jobs */
static long num_jobs_running(struct task *task, struct per_thread *threads)
{
	long i, num = 0;

	for (i = 0; i < task->opts->jobs; i++) {
		if (threads[i].running)
			num++;
	}

	return num;
}

/* Wait until all jobs are done or timeout occurs */
static int wait_for_completion(struct task *task, struct per_thread *threads)
{
	int rc = 0, earliest_timeout;
	long i;
	struct per_thread *earliest_thread;
	struct timespec tool_deadline_ts, deadline_ts, *earliest_ts;
	struct job *job;

	/* Set tool deadline */
	tool_deadline_ts = task->start_ts;
	inc_timespec(&tool_deadline_ts, task->opts->timeout, 0);

	main_lock(task);
	while (!task->aborted && task->num_jobs_active > 0) {
		/* Calculate nearest timeout */
		earliest_timeout = 0;
		earliest_ts = NULL;
		earliest_thread = NULL;

		if (task->opts->timeout > 0) {
			earliest_timeout = task->opts->timeout;
			earliest_ts = &tool_deadline_ts;
		}

		for (i = 0; i < task->opts->jobs; i++) {
			job = threads[i].job;
			if (!job || !job->timed)
				continue;
			if (task->opts->file_timeout == 0)
				continue;
			if (!earliest_ts ||
			    ts_before(&job->deadline, earliest_ts)) {
				earliest_timeout = task->opts->file_timeout;
				earliest_ts = &job->deadline;
				earliest_thread = &threads[i];
			}
		}

		/* Wait for status change or timeout */
		if (earliest_ts) {
			deadline_ts = *earliest_ts;
			rc = _main_wait_timed(task, &deadline_ts);
		} else {
			rc = _main_wait(task);
		}

		if (rc == 0)
			continue;
		if (rc != ETIMEDOUT) {
			mwarnx("Cannot wait for status change: %s",
			      strerror(rc));
			_SET_ABORTED(task);
			break;
		}

		/* Timeout handling */
		if (earliest_thread) {
			/* Per-file timeout, restart */
			_timeout_thread(earliest_thread);
			rc = 0;
		} else {
			/* Global timeout, abort */
			mwarnx("Operation timed out after %d second%s - "
			      "aborting", earliest_timeout,
			      earliest_timeout > 1 ? "s" : "");
			_SET_ABORTED(task);
			break;
		}
	}

	if (task->aborted)
		DBG("aborted");
	else
		DBG("all work done");
	_worker_wakeup_all(task);

	/* Allow jobs to finish */
	set_timespec(&deadline_ts, 0, NSEC_PER_SEC / 4);
	while (!task->aborted && num_jobs_running(task, threads) > 0) {
		DBG("waiting for %lu processes",
		    num_jobs_running(task, threads));

		if (_main_wait_timed(task, &deadline_ts))
			break;
	}

	main_unlock(task);

	return rc;
}

/* Finalize output stream */
static void close_output(struct task *task)
{
#ifdef HAVE_ZLIB
	if (task->opts->gzip) {
		gzclose(task->output_gzfd);
		return;
	}
#endif /* HAVE_ZLIB */

	if (task->output_fd != STDOUT_FILENO)
		close(task->output_fd);
}

/* Start multi-threaded processing of job queue */
static int process_queue_threaded(struct task *task)
{
	struct per_thread *threads, *thread;
	int rc;
	long i;

	tverb("Using %ld threads\n", task->opts->jobs);
	threads = mcalloc(sizeof(struct per_thread), task->opts->jobs);

	rc = 0;
	for (i = 0; i < task->opts->jobs; i++) {
		init_thread(&threads[i], task, i);
		rc = start_worker_thread(&threads[i]);
		if (rc)
			break;
	}

	if (!rc)
		wait_for_completion(task, threads);

	DBG("thread cleanup");
	for (i = 0; i < task->opts->jobs; i++) {
		thread = &threads[i];
		if (thread->running) {
			DBG("cancel %p", thread->thread);
			pthread_cancel(thread->thread);
		}
		DBG("join %p", thread->thread);
		pthread_join(thread->thread, NULL);
		add_stats(&task->stats, &thread->stats);
		cleanup_thread(thread);
	}

	free(threads);

	return rc;
}

/* Abort any remaining queued jobs and account to @stats */
static void abort_queued_jobs(struct task *task)
{
	struct job *job;

	while ((job = _dequeue_job(task))) {
		DBG("aborting job %s", job->inname);
		task->stats.num_failed++;
		job->status = JOB_FAILED;
		_complete_job(task, job);
	}
}

/* Print a summary line */
static void print_summary(struct task *task)
{
	char msg[MSG_LEN];
	size_t off = 0;
	int rc;
	struct stats *stats = &task->stats;
	struct timespec end_ts;
	int num_special;
	unsigned long num_added;

	if (task->opts->quiet)
		return;
	set_timespec(&end_ts, 0, 0);

	num_special = 0;
	num_special += stats->num_partial > 0	? 1 : 0;
	num_special += stats->num_excluded > 0	? 1 : 0;
	num_special += stats->num_failed > 0	? 1 : 0;

	num_added = stats->num_done;
	if (task->opts->ignore_failed_read)
		num_added += stats->num_partial + stats->num_failed;

	rc = snprintf(&msg[off], MSG_LEN - off, "Dumped %lu entries ",
		      num_added);
	HANDLE_RC(rc, MSG_LEN, off, out);

	if (num_special > 0) {
		rc = snprintf(&msg[off], MSG_LEN - off, "(");
		HANDLE_RC(rc, MSG_LEN, off, out);
		if (stats->num_partial > 0) {
			rc = snprintf(&msg[off], MSG_LEN - off, "%lu partial",
				      stats->num_partial);
			HANDLE_RC(rc, MSG_LEN, off, out);
			if (--num_special > 0) {
				rc = snprintf(&msg[off], MSG_LEN - off, ", ");
				HANDLE_RC(rc, MSG_LEN, off, out);
			}
		}
		if (stats->num_excluded > 0) {
			rc = snprintf(&msg[off], MSG_LEN - off, "%lu excluded",
				      stats->num_excluded);
			HANDLE_RC(rc, MSG_LEN, off, out);
			if (--num_special > 0) {
				rc = snprintf(&msg[off], MSG_LEN - off, ", ");
				HANDLE_RC(rc, MSG_LEN, off, out);
			}
		}
		if (stats->num_failed > 0) {
			rc = snprintf(&msg[off], MSG_LEN - off, "%lu failed",
				      stats->num_failed);
			HANDLE_RC(rc, MSG_LEN, off, out);
		}
		rc = snprintf(&msg[off], MSG_LEN - off, ") ");
		HANDLE_RC(rc, MSG_LEN, off, out);
	}

	rc = snprintf(&msg[off], MSG_LEN - off, "in ");
	HANDLE_RC(rc, MSG_LEN, off, out);
	snprintf_duration(&msg[off], MSG_LEN - off, &task->start_ts, &end_ts);

out:
	info("%s\n", msg);
}

static int init_task(struct task *task, struct dump_opts *opts)
{
	pthread_condattr_t attr;

	memset(task, 0, sizeof(struct task));
	set_timespec(&task->start_ts, 0, 0);
	task->opts = opts;
	pthread_mutex_init(&task->mutex, NULL);
	pthread_mutex_init(&task->output_mutex, NULL);
	pthread_cond_init(&task->worker_cond, NULL);

	pthread_condattr_init(&attr);
	if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) ||
	    pthread_cond_init(&task->cond, &attr)) {
		mwarn("Could not adjust pthread clock");
		return EXIT_RUNTIME;
	}

	return EXIT_OK;
}

struct dump_opts *dump_opts_new(void)
{
	struct dump_opts *opts = mmalloc(sizeof(struct dump_opts));

	opts->recursive = true;
	opts->read_chunk_size = DEFAULT_READ_CHUNK_SIZE;
	opts->max_buffer_size = DEFAULT_MAX_BUFFER_SIZE;

	return opts;
}

void dump_opts_free(struct dump_opts *opts)
{
	unsigned int i;

	if (!opts)
		return;

	free_strarray(&opts->exclude);
	for (i = 0; i < opts->num_specs; i++) {
		free(opts->specs[i].inname);
		free(opts->specs[i].outname);
	}
	free(opts->specs);
	free(opts);
}

void dump_opts_print(struct dump_opts *opts)
{
	unsigned int i;

	printf("DEBUG: dump_opts at %p\n", opts);
	if (!opts)
		return;
	printf("DEBUG:  add_cmd_status=%d\n", opts->add_cmd_status);
	printf("DEBUG:  append=%d\n", opts->append);
	printf("DEBUG:  dereference=%d\n", opts->dereference);
	for (i = 0; i < NUM_EXCLUDE_TYPES; i++)
		printf("DEBUG:  exclude_type[%d]=%d\n", i,
		       opts->exclude_type[i]);
	printf("DEBUG:  gzip=%d\n", opts->gzip);
	printf("DEBUG:  ignore_failed_read=%d\n", opts->ignore_failed_read);
	printf("DEBUG:  no_eof=%d\n", opts->no_eof);
	printf("DEBUG:  quiet=%d\n", opts->quiet);
	printf("DEBUG:  recursive=%d\n", opts->recursive);
	printf("DEBUG:  threaded=%d\n", opts->threaded);
	printf("DEBUG:  verbose=%d\n", opts->verbose);
	printf("DEBUG:  output_file=%s\n", opts->output_file);
	printf("DEBUG:  file_timeout=%d\n", opts->file_timeout);
	printf("DEBUG:  timeout=%d\n", opts->timeout);
	printf("DEBUG:  jobs=%ld\n", opts->jobs);
	printf("DEBUG:  jobs_per_cpu=%ld\n", opts->jobs_per_cpu);
	printf("DEBUG:  file_max_size=%zu\n", opts->file_max_size);
	printf("DEBUG:  max_buffer_size=%zu\n", opts->max_buffer_size);
	printf("DEBUG:  max_size=%zu\n", opts->max_size);
	printf("DEBUG:  read_chunk_size=%zu\n", opts->read_chunk_size);
	for (i = 0; i < opts->exclude.num; i++)
		printf("DEBUG:  exclude[%d]=%s\n", i, opts->exclude.str[i]);
	for (i = 0; i < opts->num_specs; i++) {
		printf("DEBUG:  specs[%d]:\n", i);
		printf("DEBUG:    inname=%s\n", opts->specs[i].inname);
		printf("DEBUG:    outname=%s\n", opts->specs[i].outname);
		printf("DEBUG:    is_cmd=%d\n", opts->specs[i].is_cmd);
	}
}

/* Mark file type associated with character @c as excluded */
int dump_opts_set_type_excluded(struct dump_opts *opts, char c)
{
	int i;

	for (i = 0; i < NUM_EXCLUDE_TYPES; i++) {
		if (exclude_types[i].c == c) {
			opts->exclude_type[i] = true;
			return 0;
		}
	}
	return -1;
}

/* Add entry specification defined by @iname, @outname and @op to @opts. */
void dump_opts_add_spec(struct dump_opts *opts, char *inname, char *outname,
			bool is_cmd)
{
	unsigned int i = opts->num_specs;

	opts->specs = mrealloc(opts->specs, (i + 1) * sizeof(struct dump_spec));
	opts->specs[i].inname = mstrdup(inname);
	if (outname)
		opts->specs[i].outname = mstrdup(outname);
	else
		opts->specs[i].outname = NULL;
	opts->specs[i].is_cmd = is_cmd;
	opts->num_specs++;
}

int dump_to_tar(struct dump_opts *opts)
{
	struct task task;
	int rc;
	long num_cpus;

	if (opts->jobs_per_cpu > 0) {
		num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
		if (num_cpus < 1) {
			mwarn("Cannot determine number of CPUs - assuming 1 "
			     "CPU");
			num_cpus = 1;
		}
		opts->jobs = num_cpus;
	}

	if (opts->jobs == 0 && (opts->timeout > 0 || opts->file_timeout > 0)) {
		/* Separate thread needed to implement timeout via cancel */
		opts->jobs = 1;
	}

	rc = init_task(&task, opts);
	if (rc)
		return rc;

	/* Queue initial job */
	init_queue(&task);

	/* Process queue */
	if (opts->jobs > 0)
		rc = process_queue_threaded(&task);
	else
		rc = process_queue(&task);
	abort_queued_jobs(&task);

	if (task.output_num_files > 0 && !opts->no_eof)
		write_eof(&task);

	print_summary(&task);

	close_output(&task);

	if (rc == 0 && task.aborted)
		rc = EXIT_RUNTIME;

	return rc;
}
