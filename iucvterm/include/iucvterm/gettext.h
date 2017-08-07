/*
 * iucvtty / iucvconn - IUCV Terminal Applications
 *
 * National language support (NLS) functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef __IUCVTTY_GETTEXT_H_
#define __IUCVTTY_GETTEXT_H_

#ifdef USE_NLS
#	include <locale.h>
#	include <libintl.h>
#endif


/* Gettext constants (should be supplied from Makefile) */
#ifndef GETTEXT_TEXTDOMAIN
#	define GETTEXT_TEXTDOMAIN	"iucvterm"
#endif
#ifndef GETTEXT_NLS_PATH
#	define GETTEXT_NLS_PATH		"/usr/share/locale"
#endif


/* Gettext macros */
#ifdef USE_NLS
#	define _(translatable)		gettext(translatable)
#else
#	define _(translatable)		(translatable)
#endif

#define N_(translatable)		(translatable)



/**
 * gettext_setup_locale() - Init gettext text domain using a specific locale
 * @locale:	Locale to be set.
 *
 * The function sets the program locale for LC_MESSAGES and then initializes
 * gettext.
 *
 * The @locale parameter is directly passed to the setlocale() function.
 * If @locale is "", LC_MESSAGES is set according to the environment variable.
 */
static inline int gettext_init_locale(const char *locale)
{
#ifdef USE_NLS
	if (setlocale(LC_MESSAGES, locale) == NULL)
		return -1;
	if (bindtextdomain(GETTEXT_TEXTDOMAIN, GETTEXT_NLS_PATH) == NULL)
		return -1;
	if (textdomain(GETTEXT_TEXTDOMAIN) == NULL)
		return -1;
#endif
	return 0;
}

/**
 * gettext_setup() - Initialize gettext text domain
 *
 * Calls gettext_setup_locale() with "" as locale parameter value.
 */
static inline int gettext_init(void)
{
#ifdef USE_NLS
	return gettext_init_locale("");
#else
	return 0;
#endif
}
#endif /* __IUCVTTY_GETTEXT_H_ */
