#Client part for challenge 34 (set 5)
use utf8;
use strict;
use warnings;
use MIME::Base64;
use IO::Socket::INET;
use lib ".";
use DiffieHellman;
require "./utils.pl";
require "./challenge10.pl";

main() unless caller;

sub main
{
    my $socket = new IO::Socket::INET(PeerHost => shift || '127.0.0.1',
                                      PeerPort => shift || 2019,
                                      Proto    => 'tcp') ||
                die "ERROR in Socket Creation : $!\n";
    $| = 1;
    print "[Alice] TCP Connection Success.\n";
    #No need for big primes on this test. They would just slow down the program
    my ($p, $g) = (547, 37);
    my $alice = DiffieHellman->new(p => $p, g => $g);
    #First we generate A, Alice's part of the key
    my $A = $alice->get_public_key();
    #Now we send the numbers p, g and A
    $socket->send("$p,$g,$A\n");
    $socket->flush();
    print "[Alice] Sent the numbers p, g and A\n";
    #And then, we receive B, the server's part of the key
    chomp(my $B = <$socket>);
    print "[Alice] Got B: $B\n";
    #now we get the shared key
    my $shared_key = Utils::derive_key($alice->get_shared_secret_key($B));
    print "[Alice] Shared key: $shared_key\n";
    #Choose random IV
    my $IV = Utils::random_bytes(16);
    #encrypt the message
    my $cipher_msg = AES_CBC::encrypt_data("Hello, World!", $shared_key, $IV);
    my $iv_cipher  = encode_base64($IV . $cipher_msg);
    $socket->send("$iv_cipher\n");
    $socket->flush();
    chomp(my $received   = <$socket>);
    my $decoded    = decode_base64($received);
    $IV            = substr $decoded, 0, 16;
    $cipher_msg    = substr $decoded, 16;
    my $plain_msg  = AES_CBC::decrypt_data($cipher_msg, $shared_key, $IV, 1);
    print "[Alice] Received: $plain_msg\n";
    $socket->close();

}