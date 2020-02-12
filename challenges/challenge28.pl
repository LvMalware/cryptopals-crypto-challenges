use utf8;
use strict;
use warnings;
use Digest::SHA1 qw ( sha1_hex );
require "./sha1.pl";

sub try_tamper_msg
{
    #from 'Dark Sonet' of Neil Gaiman...
    my $msg1 = "I really don't know what 'I love you' means.";
    my $msg2 = "I think it means 'Don't leave me here alone'";
    my $sha1 = SHA1->new();
    my $mac1 = $sha1->sha1_mac("Dark Sonet", $msg1);
    my $mac2 = $sha1->sha1_mac("Dark Sonet", $msg2);
    if ($mac1 ne $mac2)
    {
        print "Can't modify the message without modifying the hash!\n";
    }
    else
    {
        die "It's weird... these messages have the same hash???";
    }
}

sub try_forge_mac
{
    my $msg = "And quote the raven 'Never more'";
    my $sha = SHA1->new();
    my $mac = $sha->sha1_mac("key", $msg);
    my $err = $sha->sha1_mac("", $msg);
    if ($mac ne $err)
    {
        print "Can't produce a new MAC without the secret key!\n";
    }
    else
    {
        die "My SHA-1 MAC is broken.";
    }
}

sub test
{
    my $sha = SHA1->new();
    my $key = "SECRET KEY";
    my $msg = "SECRET MESSAGE";
    my $mac = $sha->sha1_mac($key, $msg);
    my $new = sha1_hex $key . $msg;
    print "My SHA-1 MAC: $mac\n";
    print "Perl SHA-1 MAC: $new\n";
    if ($mac eq $new)
    {
        print "SHA-1 MAC working\n";
    }
    else
    {
        die "Something went wrong with my SHA-1?";
    }
    try_tamper_msg;
    try_forge_mac;
}

test unless caller;