/*
 * s390-tools/include/zt_common.h
 *   common s390-tools definitions.
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef LIB_ZT_COMMON_H
#define LIB_ZT_COMMON_H

#define STRINGIFY_1(x)			#x
#define STRINGIFY(x)			STRINGIFY_1(x)

/* Use this macro to make constant macros usable in both assembler and
 * C code.
 *
 * Usage example:
 *  #define IMAGE_ENTRY _AC(0x10000, UL)
 */
#ifdef __ASSEMBLER__
#define _AC(X, TYPE)	X
#else
#define _AC(X, TYPE)	X##TYPE
#endif


#ifndef __ASSEMBLER__

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#else
# define UNUSED(x) x
#endif

#ifdef STATIC_ASSERT
#elif defined(__GNUC__) && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || __GNUC__ >= 5)
# define STATIC_ASSERT(test) _Static_assert((test), "(" #test ") failed");
#else
# define STATIC_ASSERT(test)
#endif

#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

#define RELEASE_STRING	STRINGIFY (S390_TOOLS_RELEASE)
#define TOOLS_LIBDIR	STRINGIFY (S390_TOOLS_LIBDIR)
#define TOOLS_SYSCONFDIR STRINGIFY (S390_TOOLS_SYSCONFDIR)
#define TOOLS_BINDIR	STRINGIFY (S390_TOOLS_BINDIR)

#define __noreturn __attribute__((noreturn))
#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define __may_alias __attribute__((may_alias))
#define __section(x) __attribute__((__section__(#x)))
#define __noinline __attribute__((__noinline__))
/* The Linux kernel (in stddef.h) and glibc (sys/cdefs.h) define
 * __always_inline. Therefore undefine it first to allow the headers
 * to be included first.
 */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#define __pa32(x) ((uint32_t)(unsigned long)(x))
#define __pa(x) ((unsigned long)(x))

#define barrier() __asm__ __volatile__("": : :"memory")

#undef MIN
#define MIN(x, y)				\
	({					\
		__typeof__(x) _x = (x);		\
		__typeof__(y) _y = (y);		\
						\
		_x < _y ? _x : _y;		\
	})

#undef MAX
#define MAX(x, y)				\
	({					\
		__typeof__(x) _x = (x);		\
		__typeof__(y) _y = (y);		\
						\
		_x > _y ? _x : _y;		\
	})

typedef unsigned long long	u64;
typedef signed long long	s64;
typedef unsigned int		u32;
typedef signed int		s32;
typedef unsigned short int	u16;
typedef signed short int	s16;
typedef unsigned char		u8;
typedef signed char		s8;

#endif /* __ASSEMBLER__ */
#endif /* LIB_ZT_COMMON_H */
