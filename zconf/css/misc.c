/*
 * Misc - Local helper functions
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


/*
 * Eliminate all the occurrences of the specified character in the string
 *
 * @param[in,out] str    String to process
 * @param[in]     symbol Character to be scanned for removal
 *
 */
void misc_str_remove_symbol(char *str, char symbol)
{
	char *source = str;
	int i, j = 0;

	for (i = 0; source[i] != '\0'; i++) {
		if (source[i] != symbol) {
			str[j] = source[i];
			j++;
		}
	}
	str[j] = '\0';
}
