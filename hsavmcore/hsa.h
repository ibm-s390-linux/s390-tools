/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_HSA_H
#define _HSAVMCORE_HSA_H

#include <stddef.h>

/*
 * The interface to a HSA memory reader.
 * This interface must be implemented by a concrete HSA memory reader.
 */
struct hsa_reader {
	/* Total HSA memory size */
	long hsa_size;
	/* Offset of HSA memory in /proc/vmcore */
	long hsa_vmcore_offset;
	/* Destroys a concrete HSA memory reader */
	void (*destroy)(struct hsa_reader *self);
	/* Reads a HSA memory block given by offset and size */
	int (*read_at)(struct hsa_reader *self, long offset, void *buf,
		       int size);
};

static inline long hsa_get_size(struct hsa_reader *self)
{
	return self->hsa_size;
}

static inline long hsa_get_vmcore_offset(struct hsa_reader *self)
{
	return self->hsa_vmcore_offset;
}

static inline void destroy_hsa_reader(struct hsa_reader *self)
{
	self->destroy(self);
}

static inline int read_hsa_at(struct hsa_reader *self, long offset, void *buf,
			      int size)
{
	return self->read_at(self, offset, buf, size);
}

/*
 * Reads total HSA memory size from /sys/kernel/debug/zcore/hsa.
 */
long get_hsa_size(const char *zcore_hsa_path);

/*
 * Returns the offset of HSA memory in /proc/vmcore.
 */
long get_hsa_vmcore_offset(const char *vmcore_path);

/*
 * Releases HSA memory.
 */
int release_hsa(const char *zcore_hsa_path);

/*
 * Returns a pointer to the enclosing struct which contains
 * the variable pointed to by the given pointer as a member.
 */
#define container_of(ptr, type, member)					\
	({								\
		const typeof(((type *)NULL)->member) *mptr = (ptr);	\
		(type *)((char *)mptr - offsetof(type, member));	\
	})

#endif
