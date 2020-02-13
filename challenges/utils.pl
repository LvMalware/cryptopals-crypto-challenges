package Utils;
use utf8;
use strict;
use warnings;
use Exporter qw (import);

our @EXPORT_OK = qw ( random_bytes );

#I use it a lot, so...
sub random_bytes{ join '', map { chr rand 256 } 1 .. $_[0] }

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