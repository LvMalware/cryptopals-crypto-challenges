use utf8;
use strict;
use bigint;
use warnings;
require "./challenge47.pl";

sub test
{
    #I think I've done this already... :p
    PKCS1_ATK::new_rsa(768);
    my $msg = "kick it, CC";
    my $pad = PKCS1_ATK::PKCS_encode($msg, 768 / 8);
    my $enc = PKCS1_ATK::get_rsa()->encrypt($pad);
    if (PKCS1_ATK::PKCS_conforming($enc))
    {
        print "PKCS1.5 - OK\n"
    }
    else
    {
        die "Something is wrong with my PKCS1.5 implementation?"
    }
    print "This may take a while...\n";
    my $dec = PKCS1_ATK::PKCS_conforming_attack($enc, 768 / 8);
    print "-"x80 . "\n";
    print "Decrypted: $dec\n";
}

test unless caller;
