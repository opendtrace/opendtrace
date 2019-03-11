#-----------------------------------------------------------------//
#
# Copyright (c) Microsoft Corporation
#
# Module Name:
#
#     mknames.pl
#
# Abstract:
#
#     This program generates the code to translate DIF subroutine ID
#     to its name.
#
#-----------------------------------------------------------------//

print <<HEADER;
/*
 * This file was automatically generated from 'dtrace.h'
 */

#include <dtrace.h>

const char *
dtrace_subrstr(dtrace_hdl_t *dtp, int subr)
{
	switch (subr) {

HEADER

while (<>) {
	my $line = $_;
	my ($sym) = $line =~ /^#define\t(DIF_SUBR_[A-Z0-9_]*).*$/;
	if (!$sym or ($sym eq "DIF_SUBR_MAX")) {
		next;
	}
	my $name = lc substr $sym, 9;
	print "\tcase $sym: return (\"$name\");\n";
	next;
}


print <<FOOTER;
	default: return (\"unknown\");
	}
}

FOOTER


