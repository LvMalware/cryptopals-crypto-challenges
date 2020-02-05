package XorUtils;
use utf8;
use strict;
use warnings;
use List::Util 'sum';
use Exporter qw ( import );
require "./pretty.pl";

our @EXPORT_OK = qw( unxor find_char );

#Statistical Distributions of English Text (used for frequency analysis)
#Avaiable at <http://www.data-compression.com/english.html> access: 01/feb/2020
my %character_freq = (
    'a' => 0.0651738, 'b' => 0.0124248, 'c' => 0.0217339, 'd' => 0.0349835,
    'e' => 0.1041442, 'f' => 0.0197881, 'g' => 0.0158610, 'h' => 0.0492888,
    'i' => 0.0558094, 'j' => 0.0009033, 'k' => 0.0050529, 'l' => 0.0331490,
    'm' => 0.0202124, 'n' => 0.0564513, 'o' => 0.0596302, 'p' => 0.0137645,
    'q' => 0.0008606, 'r' => 0.0497563, 's' => 0.0515760, 't' => 0.0729357,
    'u' => 0.0225134, 'v' => 0.0082903, 'w' => 0.0171272, 'x' => 0.0013692,
    'y' => 0.0145984, 'z' => 0.0007836, ' ' => 0.1918182
);

sub unxor { join '', map {chr(ord($_) ^ $_[1])} split //, $_[0] }

#computes the sum of frequency for each character in text
sub freq_analysis { sum map { $character_freq{lc $_} || 0 } split //, shift }

sub find_char
{
    my $cipher_text = shift;
    my %ansi_chars;
    for my $key (0 .. 255)
    {
        my $tmp_dec = unxor($cipher_text, $key);
        $ansi_chars{$key} = freq_analysis($tmp_dec);
    }
    #gets the key that produces text with higher frequency of english characters
    my $c = (sort {$ansi_chars{$a} <=> $ansi_chars{$b}} keys %ansi_chars) [-1];
    return ($c, $ansi_chars{$c}) if $c;
    return (undef, 0);
}

sub test
{
    my $s = PrettyPrinting::hex_decode("1b37373331363f78151b7f2b783431333d78" . 
        "397828372d363c78373e783a393b3736");
    my ($char, $count) = find_char($s);
    print "Xor'd with char $char (" . chr($char) . ")\n";
    print "Original text: " . unxor($s, $char) . "\n";
}

test unless caller;