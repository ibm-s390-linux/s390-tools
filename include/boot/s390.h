/*
 * s390 related definitions and functions.
 *
 * Copyright IBM Corp. 2013, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef S390_H
#define S390_H

#include "lib/zt_common.h"
#include "boot/sigp.h"

#define __LC_IPLDEV		0x0c6c
#define __LC_OS_INFO		0x0e18

#define PAGE_SIZE		_AC(4096, UL)

/* Minimum size of a stack frame in bytes */
#define STACK_FRAME_OVERHEAD	_AC(160, U)

/* Facilities */
#define UNPACK_FACILITY		_AC(161, U)

#define PSW32_ADDR_MASK   _AC(0x000000007fffffff, UL)
#define PSW_MASK_BA	  _AC(0x0000000080000000, UL)
#define PSW_MASK_EA	  _AC(0x0000000100000000, UL)
#define PSW_MASK_BIT_12	  _AC(0x0008000000000000, UL)
#define PSW_LOAD	  _AC(0x0008000080000000, UL)
#define PSW_DISABLED_WAIT _AC(0x000a000000000000, UL)


#ifndef __ASSEMBLER__

/*
 * Helper macro for exception table entries
 */
#define EX_TABLE(_fault, _target)	\
	".section .ex_table,\"a\"\n"	\
	".align	4\n"			\
	".long	(" #_fault ")\n"	\
	".long	(" #_target ")\n"	\
	".previous\n"

struct psw_t {
	uint64_t mask;
	uint64_t addr;
} __aligned(8);

struct psw32_t {
	uint32_t mask;
	uint32_t addr;
} __aligned(8);

void load_wait_psw(uint64_t, struct psw_t *);

struct _lowcore {
	uint8_t	pad_0x0000[0x0014-0x0000];	/* 0x0000 */
	uint32_t	ipl_parmblock_ptr;		/* 0x0014 */
	uint8_t	pad_0x0018[0x0080-0x0018];	/* 0x0018 */
	uint32_t	ext_params;			/* 0x0080 */
	uint16_t	ext_cpu_addr;			/* 0x0084 */
	uint16_t	ext_int_code;			/* 0x0086 */
	uint16_t	svc_ilc;			/* 0x0088 */
	uint16_t	svc_code;			/* 0x008a */
	uint16_t	pgm_ilc;			/* 0x008c */
	uint16_t	pgm_code;			/* 0x008e */
	uint32_t	data_exc_code;			/* 0x0090 */
	uint16_t	mon_class_num;			/* 0x0094 */
	uint16_t	per_perc_atmid;			/* 0x0096 */
	uint64_t	per_address;			/* 0x0098 */
	uint8_t	exc_access_id;			/* 0x00a0 */
	uint8_t	per_access_id;			/* 0x00a1 */
	uint8_t	op_access_id;			/* 0x00a2 */
	uint8_t	ar_access_id;			/* 0x00a3 */
	uint8_t	pad_0x00a4[0x00a8-0x00a4];	/* 0x00a4 */
	uint64_t	trans_exc_code;			/* 0x00a8 */
	uint64_t	monitor_code;			/* 0x00b0 */
	uint16_t	subchannel_id;			/* 0x00b8 */
	uint16_t	subchannel_nr;			/* 0x00ba */
	uint32_t	io_int_parm;			/* 0x00bc */
	uint32_t	io_int_word;			/* 0x00c0 */
	uint8_t	pad_0x00c4[0x00c8-0x00c4];	/* 0x00c4 */
	uint32_t	stfl_fac_list;			/* 0x00c8 */
	uint8_t	pad_0x00cc[0x00e8-0x00cc];	/* 0x00cc */
	uint32_t	mcck_interruption_code[2];	/* 0x00e8 */
	uint8_t	pad_0x00f0[0x00f4-0x00f0];	/* 0x00f0 */
	uint32_t	external_damage_code;		/* 0x00f4 */
	uint64_t	failing_storage_address;	/* 0x00f8 */
	uint8_t	pad_0x0100[0x0110-0x0100];	/* 0x0100 */
	uint64_t	breaking_event_addr;		/* 0x0110 */
	uint8_t	pad_0x0118[0x0120-0x0118];	/* 0x0118 */
	struct psw_t	restart_old_psw;		/* 0x0120 */
	struct psw_t	external_old_psw;		/* 0x0130 */
	struct psw_t	svc_old_psw;			/* 0x0140 */
	struct psw_t	program_old_psw;		/* 0x0150 */
	struct psw_t	mcck_old_psw;			/* 0x0160 */
	struct psw_t	io_old_psw;			/* 0x0170 */
	uint8_t	pad_0x0180[0x01a0-0x0180];	/* 0x0180 */
	struct psw_t	restart_psw;			/* 0x01a0 */
	struct psw_t	external_new_psw;		/* 0x01b0 */
	struct psw_t	svc_new_psw;			/* 0x01c0 */
	struct psw_t	program_new_psw;		/* 0x01d0 */
	struct psw_t	mcck_new_psw;			/* 0x01e0 */
	struct psw_t	io_new_psw;			/* 0x01f0 */

	/* Save areas. */
	uint64_t	save_area_sync[8];		/* 0x0200 */
	uint64_t	save_area_async[8];		/* 0x0240 */
	uint64_t	save_area_restart[1];		/* 0x0280 */
	uint8_t	pad_0x0288[0x0290-0x0288];	/* 0x0288 */

	/* Return psws. */
	struct psw_t	return_psw;			/* 0x0290 */
	struct psw_t	return_mcck_psw;		/* 0x02a0 */

	/* CPU accounting and timing values. */
	uint64_t	sync_enter_timer;		/* 0x02b0 */
	uint64_t	async_enter_timer;		/* 0x02b8 */
	uint64_t	mcck_enter_timer;		/* 0x02c0 */
	uint64_t	exit_timer;			/* 0x02c8 */
	uint64_t	user_timer;			/* 0x02d0 */
	uint64_t	system_timer;			/* 0x02d8 */
	uint64_t	steal_timer;			/* 0x02e0 */
	uint64_t	last_update_timer;		/* 0x02e8 */
	uint64_t	last_update_clock;		/* 0x02f0 */
	uint64_t	int_clock;			/* 0x02f8 */
	uint64_t	mcck_clock;			/* 0x0300 */
	uint64_t	clock_comparator;		/* 0x0308 */

	/* Current process. */
	uint64_t	current_task;			/* 0x0310 */
	uint64_t	thread_info;			/* 0x0318 */
	uint64_t	kernel_stack;			/* 0x0320 */

	/* Interrupt, panic and restart stack. */
	uint64_t	async_stack;			/* 0x0328 */
	uint64_t	panic_stack;			/* 0x0330 */
	uint64_t	restart_stack;			/* 0x0338 */

	/* Restart function and parameter. */
	uint64_t	restart_fn;			/* 0x0340 */
	uint64_t	restart_data;			/* 0x0348 */
	uint64_t	restart_source;			/* 0x0350 */

	/* Address space pointer. */
	uint64_t	kernel_asce;			/* 0x0358 */
	uint64_t	user_asce;			/* 0x0360 */
	uint64_t	current_pid;			/* 0x0368 */

	/* SMP info area */
	uint32_t	cpu_nr;				/* 0x0370 */
	uint32_t	softirq_pending;		/* 0x0374 */
	uint64_t	percpu_offset;			/* 0x0378 */
	uint64_t	vdso_per_cpu_data;		/* 0x0380 */
	uint64_t	machine_flags;			/* 0x0388 */
	uint64_t	ftrace_func;			/* 0x0390 */
	uint64_t	gmap;				/* 0x0398 */
	uint8_t	pad_0x03a0[0x0400-0x03a0];	/* 0x03a0 */

	/* Interrupt response block. */
	uint8_t	irb[64];			/* 0x0400 */

	/* Per cpu primary space access list */
	uint32_t	paste[16];			/* 0x0440 */

	uint8_t	pad_0x0480[0x0e00-0x0480];	/* 0x0480 */

	/*
	 * 0xe00 contains the address of the IPL Parameter Information
	 * block. Dump tools need IPIB for IPL after dump.
	 * Note: do not change the position of any fields in 0x0e00-0x0f00
	 */
	uint64_t	ipib;				/* 0x0e00 */
	uint32_t	ipib_checksum;			/* 0x0e08 */
	uint64_t	vmcore_info;			/* 0x0e0c */
	uint8_t	pad_0x0e14[0x0e18-0x0e14];	/* 0x0e14 */
	uint64_t	os_info;			/* 0x0e18 */
	uint8_t	pad_0x0e20[0x0f00-0x0e20];	/* 0x0e20 */

	/* Extended facility list */
	uint64_t	stfle_fac_list[32];		/* 0x0f00 */
	uint8_t	pad_0x1000[0x11b0-0x1000];	/* 0x1000 */
	uint64_t	vector_save_area_addr;		/* 0x11b0 */
	/* 64 bit extparam used for pfault/diag 250: defined by architecture */
	uint64_t	ext_params2;			/* 0x11B8 */
	uint8_t	pad_0x11c0[0x1200-0x11C0];	/* 0x11C0 */

	/* CPU register save area: defined by architecture */
	uint64_t	floating_pt_save_area[16];	/* 0x1200 */
	uint64_t	gpregs_save_area[16];		/* 0x1280 */
	struct psw_t	psw_save_area;			/* 0x1300 */
	uint8_t	pad_0x1310[0x1318-0x1310];	/* 0x1310 */
	uint32_t	prefixreg_save_area;		/* 0x1318 */
	uint32_t	fpt_creg_save_area;		/* 0x131c */
	uint8_t	pad_0x1320[0x1324-0x1320];	/* 0x1320 */
	uint32_t	tod_progreg_save_area;		/* 0x1324 */
	uint32_t	cpu_timer_save_area[2];		/* 0x1328 */
	uint32_t	clock_comp_save_area[2];	/* 0x1330 */
	uint8_t	pad_0x1338[0x1340-0x1338];	/* 0x1338 */
	uint32_t	access_regs_save_area[16];	/* 0x1340 */
	uint64_t	cregs_save_area[16];		/* 0x1380 */
	uint8_t	pad_0x1400[0x1800-0x1400];	/* 0x1400 */

	/* Transaction abort diagnostic block */
	uint8_t	pgm_tdb[256];			/* 0x1800 */

	/* align to the top of the prefix area */
	uint8_t	pad_0x1900[0x2000-0x1900];	/* 0x1900 */
} __packed __aligned(8192);

#define S390_lowcore (*((struct _lowcore *) 0))


static __always_inline int page_is_valid(unsigned long addr)
{
	unsigned long tmp;
	int rc;

	asm volatile(
		"0:     ic      %1,%2\n"
		"1:     lhi     %0,1\n"
		"2:\n"
		".pushsection .fixup, \"ax\"\n"
		"3:     xr      %0,%0\n"
		"       jg      2b\n"
		".popsection\n"
		EX_TABLE(0b, 3b) EX_TABLE(1b, 3b)
		: "=d" (rc), "=d" (tmp)
		: "Q" (*(unsigned long *) addr)
		: "cc");
	return rc;
}

static __always_inline uint32_t csum_partial(const void *buf, int len, uint32_t sum)
{
	register unsigned long reg2 asm("2") = (unsigned long) buf;
	register unsigned long reg3 asm("3") = (unsigned long) len;

	asm volatile(
		"0:     cksm    %0,%1\n"        /* do checksum on longs */
		"       jo      0b\n"
		: "+d" (sum), "+d" (reg2), "+d" (reg3) : : "cc", "memory");
	return sum;
}

#define __ctl_store(array, low, high) ({		    \
	typedef struct { char _[sizeof(array)]; } __may_alias addrtype;\
	asm volatile(					    \
		"	stctg	%1,%2,%0\n"		    \
		: "=Q" (*(addrtype *)(&array))		    \
		: "i" (low), "i" (high));		    \
})

#define __ctl_load(array, low, high) ({			    \
	typedef struct { char _[sizeof(array)]; } __may_alias addrtype; \
	asm volatile(					    \
		"	lctlg	%1,%2,%0\n"			\
		: : "Q" (*(addrtype *)(&array)),		\
		  "i" (low), "i" (high));			\
})

static __always_inline void __ctl_set_bit(unsigned int cr, unsigned int bit)
{
	unsigned long reg;

	__ctl_store(reg, cr, cr);
	reg |= 1UL << bit;
	__ctl_load(reg, cr, cr);
}

/*
 * DIAG 308 support
 */
enum diag308_subcode {
	DIAG308_REL_HSA	  = 2,
	DIAG308_IPL	  = 3,
	DIAG308_DUMP	  = 4,
	DIAG308_SET	  = 5,
	DIAG308_STORE	  = 6,
	DIAG308_SET_PV	  = 8,
	DIAG308_UNPACK_PV = 10,
};

enum diag308_rc {
	DIAG308_RC_OK	      = 0x0001,
	DIAG308_RC_NO_CONF    = 0x0102,
};

static __always_inline unsigned long diag308(unsigned long subcode, void *addr)
{
	register unsigned long _addr asm("0") = (unsigned long) addr;
	register unsigned long _rc asm("1") = 0;

	asm volatile(
		"	diag	%0,%2,0x308\n"
		"0:\n"
		: "+d" (_addr), "+d" (_rc)
		: "d" (subcode) : "cc", "memory");
	return _rc;
}

/*
 * Store CPU address
 */
static __always_inline unsigned short stap(void)
{
	unsigned short cpu_address;

	asm volatile("stap %0" : "=m" (cpu_address));
	return cpu_address;
}

/*
 * Program the clock comparator
 */
static __always_inline void set_clock_comparator(uint64_t time)
{
	asm volatile("sckc %0" : : "Q" (time));
}

/*
 * Program the CPU timer
 */
static __always_inline void set_cpu_timer(uint64_t timer)
{
	asm volatile("spt %0" : : "Q" (timer));
}

/*
 * Get current time (store clock)
 */
static __always_inline unsigned long long get_tod_clock(void)
{
	unsigned long long clk;

	asm volatile("stck %0" : "=Q" (clk) : : "cc");
	return clk;
}

/*
 * Get ID of current CPU
 */
struct cpuid {
	unsigned int version:8;
	unsigned int ident:24;
	unsigned int machine:16;
	unsigned int unused:16;
} __packed __aligned(8);

static __always_inline void get_cpu_id(struct cpuid *ptr)
{
	asm volatile("stidp %0" : "=Q" (*ptr));
}

/*
 * Check if we run under z/VM
 */
static __always_inline int is_zvm(void)
{
	struct cpuid cpuid;

	get_cpu_id(&cpuid);
	return cpuid.version == 0xff;
}

/* To avoid conflicts add a macro guard since __vector128 is also
 * defined in 'linux/asm/types.h'.
 */
#ifndef _S390_TYPES_H
/*
 * Vector register definition
 */
typedef struct {
	uint32_t u[4];
} __vector128;
#endif

/*
 * Save vector registers
 */
static __always_inline void save_vx_regs(__vector128 *vxrs)
{
	typedef struct { __vector128 _[32]; } addrtype;

	asm volatile(
		"	la	1,%0\n"
		"	.word	0xe70f,0x1000,0x003e\n"	/* vstm 0,15,0(1) */
		"	.word	0xe70f,0x1100,0x0c3e\n"	/* vstm 16,31,256(1) */
		: "=Q" (*(addrtype *) vxrs) : : "1");
}

/*
 * Save vector registers safe
 */
static __always_inline void save_vx_regs_safe(__vector128 *vxrs)
{
	unsigned long cr0;

	__ctl_store(cr0, 0, 0);
	__ctl_set_bit(0, 17);
	__ctl_set_bit(0, 18); /* AFP-register-control */
	save_vx_regs(vxrs);
	__ctl_load(cr0, 0, 0);
}

#define MAX_FACILITY_BIT (256*8)	/* stfle_fac_list has 256 bytes */

static __always_inline int __test_facility(unsigned long nr, void *facilities)
{
	unsigned char *ptr;

	if (nr >= MAX_FACILITY_BIT)
		return 0;
	ptr = (unsigned char *) facilities + (nr >> 3);
	return (*ptr & (0x80 >> (nr & 7))) != 0;
}

/*
 * The test_facility function uses the bit odering where the MSB is bit 0.
 * That makes it easier to query facility bits with the bit number as
 * documented in the Principles of Operation.
 */
static __always_inline int test_facility(unsigned long nr)
{
	return __test_facility(nr, &S390_lowcore.stfle_fac_list);
}

static __always_inline unsigned long __stfle_asm(uint64_t *stfle_fac_list, unsigned int size)
{
	register unsigned long reg0 asm("0") = size - 1;

	asm volatile(
		".insn s,0xb2b00000,0(%1)" /* stfle */
		: "+d" (reg0)
		: "a" (stfle_fac_list)
		: "memory", "cc");
	return reg0;
}

/**
 * stfle - Store facility list extended
 * @stfle_fac_list: array where facility list can be stored
 * @size: size of passed in array in double words
 */
static __always_inline void stfle(uint64_t *stfle_fac_list, unsigned int size)
{
	unsigned long nr;

	asm volatile(
		"	.insn s,0xb2b10000,0(0)\n" /* stfl */
		"0:\n"
		EX_TABLE(0b, 0b)
		: "+m" (S390_lowcore.stfl_fac_list));
	nr = 4; /* bytes stored by stfl */
	memcpy(stfle_fac_list, &S390_lowcore.stfl_fac_list, 4);
	if (S390_lowcore.stfl_fac_list & 0x01000000) {
		/* More facility bits available with stfle */
		nr = __stfle_asm(stfle_fac_list, size);
		nr = MIN((nr + 1) * 8, size * 8UL);
	}
	memset((char *) stfle_fac_list + nr, 0, size * 8 - nr);
}

#endif /* __ASSEMBLER__ */
#endif /* S390_H */
