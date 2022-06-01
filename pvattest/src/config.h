/*
 * Config file.
 * Must be include before any other header.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
#ifndef PVATTEST_CONFIG_H
#define PVATTEST_CONFIG_H
#define GETTEXT_PACKAGE "pvattest"

#ifdef __GNUC__
#ifdef __s390x__
#ifndef PVATTEST_NO_PERFORM
#define PVATTEST_COMPILE_PERFORM
#endif
#endif
#endif

#ifdef __clang__
#ifdef __zarch__
#ifndef PVATTEST_NO_PERFORM
#define PVATTEST_COMPILE_PERFORM
#endif
#endif
#endif

#endif /* PVATTEST_CONFIG_H */
