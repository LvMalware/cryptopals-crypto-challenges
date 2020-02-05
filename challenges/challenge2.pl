use utf8;
use strict;
use warnings;
require "./pretty.pl";

sub xor_str
{
    return join '', map {
            chr(ord(substr($_[0], $_)) ^ ord(substr($_[1], $_)))
        } (0 .. length($_[0]) - 1);
}

my $str1 = PrettyPrinting::hex_decode("1c0111001f010100061a024b53535009181c");
my $str2 = PrettyPrinting::hex_decode("686974207468652062756c6c277320657965");
my $str3 = PrettyPrinting::hex_encode(xor_str($str1, $str2));
print "\"$str1\" xor \"$str2\" = $str3\n";