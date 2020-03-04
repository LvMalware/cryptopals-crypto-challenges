package RSA_SIG;
use utf8;
use strict;
use bigint;
use warnings;
use Math::BigInt;
use ntheory "rootint";
use Digest::SHA qw(sha1_hex);
use lib ".";
eval 'use RSA';

#according with rfc 3447, this is the 15-byte ASN.1 value for SHA1
my $ASN1 = "3021300906052b0e03021a05000414";

sub rsa_sign { $_[0]->decrypt($_[1]) }

sub rsa_verify
{
    my ($rsa, $sig, $msg) = @_;
    my $signature = "000" . RSA::_expmod(hex $sig, 3, $rsa->{n})->to_hex();
    if ($signature =~ /0001ff00$ASN1(.{39})/)
    {
        return sha1_hex($msg) =~ /^$1/;
    }
    return 0
}

sub fake_sig
{
    my ($msg, $len) = @_;
    my $sig = "0001ff00" . $ASN1 . sha1_hex($msg);
    $sig .= "00" x (($len + 7)/8 - length($sig)/2);
    Math::BigInt->new(rootint(hex($sig), 3))->to_hex()
}

sub test
{
    my $msg = 'hi mom';
    my $sig = fake_sig($msg, 1024);
    my $rsa = RSA->new(key_len => 1024);
    if (rsa_verify($rsa, $sig, $msg))
    {
        print "It works!\n"
    }
    else
    {
        die "I'm a failure :("
    }
}

test unless caller;
