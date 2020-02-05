package PKCS7_V;
use utf8;
use strict;
use warnings;
#use Try::Tiny; #Exception handling (unnecessary)

sub padded
{
    my $data  = shift;
    my $last  = ord(substr $data, -1, 1);
    my $block = substr $data, -$last;
    for my $byte (split //, $block)
    {
        return 0 if ord($byte) != $last;
    }
    1;
}

sub unpad
{
    my $input    = shift;
    #easyest way to throw an exception in Perl
    die ("Invalid padding") unless padded($input);
    my $pad_char = ord substr $input, -1, 1;
    my $data_len = length($input) - $pad_char;
    substr $input, 0, $data_len;
}

sub test
{
    my @test_strings = ("ICE ICE BABY\x04\x04\x04\x04",
                        "ICE ICE BABY\x05\x05\x05\x05",
                        "ICE ICE BABY\x01\x02\x03\x04",
                        "VALID PADDING\x03\x03\x03",
                        "THIS IS INVALID\x05");
    
    for my $data (@test_strings)
    {
        #Exception handling with eval() seems to work just fine.
        print "Invalid padding!\n" unless (
            eval { print "UNPADDED: " . unpad($data) . "\n" }
            );
    }
}

test unless caller;