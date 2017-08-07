/*
 * vmdump - z/VM dump conversion library
 *
 * Dump convert function: Converts VMDUMP to LKCD dump
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lkcd_dump.h"
#include "vm_dump.h"

int vmdump_convert(const char* inputFileName, const char* outputFileName,
	       const char* progName)
{
	/* Do the conversion */
	try {
		switch(VMDump::getDumpType(inputFileName)){
			case Dump::DT_VM64_BIG:
			{
				LKCDDump64* lkcddump;
				VMDump64Big* vmdump;

				vmdump = new VMDump64Big(inputFileName);
				vmdump->printInfo();
				lkcddump = new LKCDDump64(vmdump,
						vmdump->getRegisterContent());
				lkcddump->writeDump(outputFileName);
				delete vmdump;
				delete lkcddump;
				break;
			}
			case Dump::DT_VM64:
			{
				LKCDDump64* lkcddump;
				VMDump64* vmdump;

				vmdump = new VMDump64(inputFileName);
				vmdump->printInfo();
				lkcddump = new LKCDDump64(vmdump,
						vmdump->getRegisterContent());
				lkcddump->writeDump(outputFileName);
				delete vmdump;
				delete lkcddump;
				break;
			}
			case Dump::DT_VM32:
			{
				LKCDDump32* lkcddump;
				VMDump32* vmdump;

				vmdump = new VMDump32(inputFileName);
				vmdump->printInfo();
				lkcddump = new LKCDDump32(vmdump,
						vmdump->getRegisterContent());
				lkcddump->writeDump(outputFileName);
				delete vmdump;
				delete lkcddump;
				break;
			}
			default:
				throw DumpException("This is not a vmdump");
		}
	} catch (DumpException ex) {
		printf("%s: %s\n", progName, ex.what());
		fflush(stdout);
		return 1;
	}
	return 0;
}
