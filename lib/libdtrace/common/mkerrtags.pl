#-----------------------------------------------------------------//
#
# Copyright (c) Microsoft Corporation
#
# Module Name:
#
#     mkerrtags.pl
#
# Abstract:
#
#     This program generates error tag strings from their definition.
#
#-----------------------------------------------------------------//

print <<HEADER;
/*
 * This file was automatically generated from 'dt_errtags.h'
 */

#include <dt_errtags.h>

static const char *const _dt_errtags[] = {

HEADER

while (<>) {
	my $line = $_;
	my ($sym, $comment) = $line =~ /^\s*(D_[A-Z0-9_]*)\s*,(.*)$/;
	if (!$sym) {
		next;
	}

	print "\t\"$sym\",$comment\n";
	next;
}


print <<FOOTER;
};

static const int _dt_ntag = sizeof (_dt_errtags) / sizeof (_dt_errtags[0]);

const char *
dt_errtag(dt_errtag_t tag)
{
	return (_dt_errtags[(tag > 0 && tag < _dt_ntag) ? tag : 0]);
}

FOOTER


