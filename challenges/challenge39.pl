use utf8;
use bigint;
use strict;
use warnings;
use lib ".";
use RSA;

my $message = "My secret message";
my $rsa = RSA->new(key_len => 1024);
my $enc = $rsa->encrypt($message);
print "Encrypted: $enc\n";
my $dec = $rsa->decrypt($enc);
print "Decrypted: $dec\n";
if ($message eq $dec)
{
    print "It works!\n"
}
else
{
    print "I'm a failure :(\n"
}