use utf8;
use strict;
use bigint;
use warnings;
use ntheory qw(invmod);
use Digest::SHA qw(sha1_hex);
use lib ".";
eval "use DSA";

sub test
{
    my $p = hex(
        '800000000000000089e1855218a0e7dac38136ffafa72eda7' .
        '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6' .
        '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe' .
        'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2' .
        'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87' .
        '1a584471bb1'
    );
 
    my $q = hex('f4f47f05794b256174bba6e9b396a7707e563c5b');
 
    my $g = hex(
        '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119' .
        '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5' .
        '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047' .
        '0f5b64c36b625a097f1651fe775323556fe00b3608c887892' .
        '878480e99041be601a62166ca6894bdd41a7054ec89f756ba' .
        '9fc95302291'
    );
    my $msg1 = "Hello, world";
    my $msg2 = "Goodbye, world";
    
    #########################################################
    #                   Test 1: G = 0                       #
    ########################################################
    #Doesn't work, since my DSA implementation wont accept r = 0, it will create
    #an infinite loop... let's skip this

    #########################################################
    #                   Test 2: G = P+1                     #
    ########################################################

    my $dsa = DSA->new(h => \&sha1_hex, p => $p, q => $q, g => $p+1);
    my @sig = $dsa->sign($msg1);
    print "Signature: @sig\n";
    
    if ($dsa->verify(@sig, $msg1))
    {
        print "Real signature accepted!\n";
    }
    #now, let's fake a signature!
    my $z = int rand 100;
    my $r = DSA::expmod($dsa->{y}, $z, $p) % $q;
    my $s = ($r * invmod($z, $q)) % $q;
    print "Fake signature: $r $s\n";
    if ($dsa->verify($r, $s, $msg1))
    {
        print "Fake signature accepted for: $msg1\n";
    }
    else
    {
        die "I am a failure! :(   "
    }
    if ($dsa->verify($r, $s, $msg2))
    {
        print "Fake signature accepted for: $msg2\n";
    }
    else
    {
        die "I am a failure! :(   "
    }
}

test unless caller;
