#!/bin/sh
#
# Test program for chiucvallow
#
#
# Copyright IBM Corp. 2009, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

# set -x

# test data file
test_data=`mktemp /tmp/chiucvallow.testdata.XXXXXX`
LOG_FILE=/dev/null
TEST_PROG=${1:-../bin/chiucvallow.in}


# run test program (we can savely use the .in version here)
tprg() {
	test -x $TEST_PROG || chmod +x $TEST_PROG
	$TEST_PROG $@ >$LOG_FILE 2>&1
	return $?
}

failed() {
	echo $1
	exit 3
}

# Init
test -r "$test_data" || failed "Failed to create temporary file"
trap "rm -f $test_data" EXIT TERM INT


# 1: Test special characters
cat > $test_data <<'EoData'
# user ID filter with some exotic user ID names
#
# z/VM user ID consists mainly of alphanumeric characters.
# Additional characters like @#_-$ are also allowed. However, @ and # are not
# recommended. Additional characters can be configured.
#
# To use a common set of all the values possible, the iucv terminal tools
# uses alphnumeric and underscore. The chiucvallow program also allows to use
# the dollar sign ($).
#
# All other characters must not be used.
#
#
NORMAL
# underscores are allowed
WITH_
# dollar sign is allowed for chiucvallow only
WITH$
$VAR
$ALLOC$
$$$$$$$$
12345678
EoData
tprg -V $test_data || failed "1: Failed: verify special z/VM user ID chars"


# 2: Test special characters
cat > $test_data <<'EoData'
# the following entry fails
-HYPHEN
EoData
tprg -V $test_data && failed "2: Failed: verify special z/VM user ID chars"


# 3: Test maximum number of filter entries
for i in `seq 1 500`; do printf "ID%05d\n" $i ; done > $test_data
tprg -V $test_data || failed "3: Failed: verify correct numbers of filter entries"

# 4: Test verification fails because of too many filter entries
for i in `seq 1 501`; do printf "ID%05d\n" $i ; done > $test_data
tprg -V $test_data && failed "4: Failed: verify correct numbers of filter entries"

# 5: Test verification fails because of too many filter entries
for i in `seq 1 510`; do printf "ID%05d\n" $i ; done > $test_data
tprg -V $test_data && failed "5: Failed: verify correct numbers of filter entries"


# 6: Test filter size (final size of filter entries, not file size)
cat > $test_data <<'EoData'
# z/VM user ID filter file for testing chiucvallow
#
# This file defines 500 user IDs with few comments to
# increase the file size.
#
# The comments must not be ignored for file size calculation, because
# comments are not part of the hvc_iucv_allow sysfs attribute.
#
# The size of the z/VM user ID filer that is reported by chiucvallow
# must be: 4000 bytes = 7 * 500 + 500
#          (500 user IDs a 7 bytes (in length) + 500 carriage returns)
EoData
for i in `seq 1 500`; do printf "ID%05d\n" $i ; done >> $test_data
echo '# End of z/VM user ID filter file ' >> $test_data
test `stat -c%s $filename 2>/dev/null || echo 0` -ge 4095 \
  && failed "6: Failed to create test pre-req"
tprg -V $test_data || failed "6: Failed: verify filter with correct filter size"

# 7: Test filter size that exceed 4K (500 * 8 + 500 = 4500)
for i in `seq 1 500`; do printf "ID%06d\n" $i ; done > $test_data
tprg -V $test_data && failed "7: Failed: verify filter with incorred filter size"

# 8: Test valid wildcard filter entries
cat > $test_data <<'EoData'
# z/VM user ID filter for testing chiucvallow
#
# This file contains wildcard filter entries that must be considered as
# valid.
#
ID100*
A*
AB*
ABC*
ABCD*
ABCDE*
ABCDEF*
ABCDEFG*
12345678
EoData
tprg -V $test_data || failed "8: Failed: verify filter with valid wildcards"

# 9: Test wildcard filter entries that are not valid
for ent in "*" "*A" "ABC*A" "A2345678*"; do
	echo "$ent" > $test_data
	tprg -V $test_data && failed "9: Failed: verified invalid wildcard: '$ent'"
done

exit 0
