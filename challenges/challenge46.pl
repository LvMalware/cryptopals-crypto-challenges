use utf8;
use strict;
use bigint;
use warnings;
use MIME::Base64;
use Math::BigFloat;
use lib '.';
eval 'use RSA';

my $oracle = RSA->new(key_len => 1024);

sub rsa_is_even { RSA::_expmod($_[0], $oracle->{d}, $oracle->{n}) & 1 }

my $unknown = decode_base64(
    'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IG' .
    'Fyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
);

sub parity_decrypt
{
    my $ciphert = shift;
    my $steps   = int Math::BigFloat->new($oracle->{n})->blog(2)->bceil();
    my $lower   = 0;
    my $upper   = $oracle->{n};
    my $factor  = RSA::_expmod(2, $oracle->{e}, $oracle->{n});
    print "N: " . $oracle->{n} . "\n";
    print "It will take $steps iterations...\n";
    for my $i (0 .. $steps)
    {
        ($ciphert *= $factor) %= $oracle->{n};
        
        if (rsa_is_even($ciphert))
        {
            ($lower += $upper) /= 2;
        }
        else
        {
            ($upper += $lower) /= 2;
        }

        print RSA::_int_str(int $upper) . "\n";
    }
    RSA::_int_str(int $upper);
}

sub test
{
    my $encrypted = $oracle->encrypt($unknown);
    my $decrypted = parity_decrypt($encrypted);
    print "-"x80 . "\n";
    print "Decrypted: $decrypted\n";
}

test unless caller;
