package Challenge5;
use utf8;
use strict;
use warnings;
use Exporter;
require "./pretty.pl";

our @EXPORT_OK = qw ( xor_encrypt );

sub xor_encrypt
{
    my $input   = shift;
    my $key     = shift;
    my ($i, $j) = (0,0);
    my $output  = "";
    while (length($output) < length($input))
    {
        $output .= chr(
            ord(substr($input, $i++)) ^ ord(substr($key, $j++))
        );
        
        $j = 0 if ($j >= length($key));
    }
    return PrettyPrinting::hex_encode($output);
}

sub test
{
    my $plain = "Burning 'em, if you ain't quick and nimble\n" .
                "I go crazy when I hear a cymbal";
    my $cipher = xor_encrypt($plain, "ICE");
    
    my $original = xor_encrypt(PrettyPrinting::hex_decode($cipher), "ICE");
    print "Plain text: $plain\n";
    print "Xor'd text: " . $cipher . "\n";
    print "Back to plain: " . PrettyPrinting::hex_decode($original) . "\n";
}

test unless caller;