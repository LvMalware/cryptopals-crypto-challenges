use utf8;
use Math::BigInt;
use strict;
use warnings;
use lib ".";
use DiffieHellman;

use constant {
    P => Math::BigInt->new(
            '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024' .
            'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd' .
            '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec' .
            '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f' .
            '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361' .
            'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552' .
            'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff' .
            'fffffffffffff'),
    G => 2
};

sub test
{
    #The most classic example...
    my $alice    = DiffieHellman->new(p => P, g => G);
    my $bob      = DiffieHellman->new(p => P, g => G);
    print "Generating public keys...\n";
    my $alice_pk = $alice->get_public_key();
    my $bob_pk   = $bob->get_public_key();
    print "Alice (PK): $alice_pk\n";
    print "Bob (PK): $bob_pk\n";
    print "Generating shared keys...\n";
    my $alice_sk = $alice->get_shared_secret_key($bob_pk);
    my $bob_sk   = $bob->get_shared_secret_key($alice_pk);
    print "Alice (SK): $alice_sk\n";
    print "Bob (SK): $bob_sk\n";
    if ($bob_sk == $alice_sk)
    {
        print "Key exchange is working!\n";
    }
    else
    {
        die "I'm a failure :("
    }
}

test unless caller;