use utf8;
use strict;
use bigint;
use warnings;
use ntheory qw(invmod);
use Digest::SHA qw(sha256_hex);
use Math::BigInt::Random qw(random_bigint);
use lib '.';
eval 'use RSA'; #this avoid vscodium to display a module not found error
require "./utils.pl";

my @already_decrypted;
my $rsa = RSA->new(key_len => 1024);

sub rsa_server_decrypt
{
    my $encrypted = shift;
    my $checksum  = sha256_hex("$encrypted");
    die "already decrypted!" if (grep /^$checksum/, @already_decrypted);
    push @already_decrypted, $checksum;
    $rsa->decrypt($encrypted);
}

sub unpadded_message_recovery
{
    my ($encrypted, $n, $e) = @_;
    #Any number S > 1, that S % N = 1 ... it can just be N+1
    my $S = $n + 1;
    my $C = (Utils::expmod($S, $e, $n) * $encrypted) % $n;
    my $p = rsa_server_decrypt($C);
    my $i = RSA::_str_int($p);
    RSA::_int_str(($i * invmod($S, $n)) % $n);
}

sub test
{
    my $message   = "My secret message!";
    my $encrypted = $rsa->encrypt($message);
    my $decrypted = unpadded_message_recovery($encrypted, $rsa->{n}, $rsa->{e});
    print "Decrypted: $decrypted\n";
    if ($message eq $decrypted)
    {
        print "\nIt works!\n"
    }
    else
    {
        die "I'm a failure :("
    }
}

test unless caller;