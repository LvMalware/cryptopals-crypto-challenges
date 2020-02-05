package ECB_DETECT;
use utf8;
use strict;
use warnings;
use Exporter qw (import);
require "./pretty.pl";

our @EXPORT_OK = qw( detect_ecb is_ecb );

sub split_16bytes { map { substr $_[0], $_ * 16, 16 } 0 .. length($_[0])/16 }

sub detect_ecb
{
    my $data   = shift;
    my @blocks = map { quotemeta ($_) } split_16bytes($data);
    my @repetitions;
    push(@repetitions, $data =~ s/$_//g) for @blocks;
    my @sorted_rep = sort @repetitions;
    return $sorted_rep[-1];
}

sub is_ecb { detect_ecb(shift) > 1}

sub test
{
    my $file;
    open($file, "< :encoding(UTF-8)", "8.txt");
    my $index = 0;
    my %ecb_lines;
    while (my $line = <$file>)
    {
        print "Processing line $index\n";
        my $rep_count = detect_ecb(PrettyPrinting::hex_decode($line));
        $ecb_lines{$index} = [$rep_count, $line];
        $index ++;
    }

    my @best = sort {$ecb_lines{$a}->[0] <=> $ecb_lines{$b}->[0]} keys %ecb_lines;
    my $line = $best[-1];
    my ($count, $data) = @{$ecb_lines{$line}};
    print "-"x80 . "\n";
    print "The line $line is ECB encrypted.\n";
    print "Number of repeated blocks: $count\n";
    print "Line content: $data\n";
}

test unless caller;