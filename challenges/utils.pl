package Utils;
use utf8;
use strict;
use bigint;
use warnings;
use Exporter qw (import);
use Digest::SHA qw( sha1_hex );

our @EXPORT_OK = qw ( random_bytes );

#I use it a lot, so...
sub random_bytes { join '', map { chr rand 256 } 1 .. $_[0] }

sub derive_key { substr sha1_hex("$_[0]"), 0, $_[1] || 16 }

sub choose_key
{
    my $words = "/usr/share/dict/words";
    my $count = `wc -l $words | cut -d " " -f1`;
    my $index = int rand $count;
    my $file;
    open $file, "< :encoding(UTF-8)", $words;
    while ($index)
    {
        <$file>;
        $index --;
    }
    my $secret_key = <$file>;
    chomp $secret_key;
    close $file;
    $secret_key;
}

#Modular Exponetial function from Rosetta Code
#Avaiable at https://rosettacode.org/wiki/Modular_exponentiation#Perl
#Accessed in 18/feb/2020
sub expmod
{
    my($a, $b, $n) = @_;
    my $c = 1;
    do {
        ($c *= $a) %= $n if $b % 2;
        ($a *= $a) %= $n;
    } while ($b = int $b/2);
    $c;
}