package Utils;
use utf8;
use strict;
use warnings;
use Exporter qw (import);

our @EXPORT_OK = qw ( random_bytes );

#I use it a lot, so...
sub random_bytes{ join '', map { chr rand 256 } 0 .. $_[0] }