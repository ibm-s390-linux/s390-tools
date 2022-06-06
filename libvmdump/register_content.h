/*
 * vmdump - z/VM dump conversion library
 *
 * Register content classes
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef REGISTER_CONTENT_H
#define REGISTER_CONTENT_H

#include <stdint.h>

#define MAX_CPUS 512

class RegisterSet64
{
public:
	uint64_t gprs[16];
	uint64_t crs[16];
	uint32_t acrs[16];
	uint64_t fprs[16];
	uint32_t fpCr;
	uint64_t psw[2];
	uint32_t prefix;
	uint64_t cpuTimer;
	uint64_t clkCmp;
};

class RegisterSet32
{
public:
	uint32_t gprs[16];
	uint32_t crs[16];
	uint32_t acrs[16];
	uint64_t fprs[4];
	uint32_t psw[2];
	uint32_t prefix;
	uint64_t cpuTimer;
	uint64_t clkCmp;
};

class RegisterContent64{
public:
	RegisterContent64(void);
	RegisterContent64(const RegisterContent64&);
	RegisterSet64 getRegisterSet(int cpu);
	void addRegisterSet(const RegisterSet64&);
	inline int getNumCpus(void) const { return nrCpus; }
	RegisterContent64& operator=(const RegisterContent64&) = default;

	RegisterSet64 regSets[MAX_CPUS];
private:
	int nrCpus;

};

class RegisterContent32{
public:
	RegisterContent32(void);
	RegisterContent32(const RegisterContent32&);
	RegisterSet32 getRegisterSet(int cpu);
	void addRegisterSet(const RegisterSet32&);
	inline int getNumCpus(void) const { return nrCpus; }
	RegisterContent32& operator=(const RegisterContent32&) = default;

	RegisterSet32 regSets[MAX_CPUS];
private:
	int nrCpus;
};

#endif /* REGISTER_CONTENT_H */
