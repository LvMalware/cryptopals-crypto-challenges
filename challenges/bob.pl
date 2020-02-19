#Server part for challenge 34 (set 5)
use utf8;
use strict;
use warnings;
use MIME::Base64;
use IO::Socket::INET;
use lib ".";
use DiffieHellman;
require "./utils.pl";
require "./challenge10.pl";

main(2019) unless caller;

sub main
{
    #
    my $port = shift;
    my $addr = shift || '127.0.0.1';
    #Try bind to a port and if it fails, bind to that port + 1.
    #this will be used to simulate a type of port spoofing, making the client
    #connect to a port with the attacker that will send the message to the real
    #server on another port.
    #I know it's not ideal, but let's just pretend, shall we?
    my $sock = IO::Socket::INET->new(Listen    => 5,
                                     LocalAddr => $addr,
                                     LocalPort => $port,
                                     Proto     => 'tcp') ||
                IO::Socket::INET->new(Listen    => 5,
                                      LocalAddr => $addr,
                                      LocalPort => ++$port,
                                      Proto     => 'tcp');
    $| = 1;
    print "[Bob] Server listening for connections on port $port\n";
    server_loop($sock);

}

sub server_loop
{
    my $sock = shift;
    while (1)
    {
        my $cli_sock = $sock->accept();
        my $cli_addr = $cli_sock->peerhost();
        my $cli_port = $cli_sock->peerport();
        print "[Bob] Accepted connection from $cli_addr:$cli_port\n";
        #Only one client at time... as I said, not ideal
        handle_client($cli_sock);
    }
}

sub handle_client
{
    my $cli_sock = shift;
    #First, the client will send the needed data for a key exchange
    #A->B
    #Send "p", "g", "A"
    chomp(my $key_exchange_params = <$cli_sock>);
    #the numbers p, g and A will be sepparated by a ','
    my ($p, $g, $A) = split /,/, $key_exchange_params;
    print "[Bob] Got P: $p\n";
    print "[Bob] Got G: $g\n";
    print "[Bob] Got A: $A\n";
    my $bob = DiffieHellman->new(p => $p, g=> $g);
    #now, the server will send it's part
    #B->A
    #Send "B"
    $cli_sock->send($bob->get_public_key() . "\n");
    $cli_sock->flush();
    #now we get the shared key
    my $shared_key = Utils::derive_key($bob->get_shared_secret_key($A));
    print "[Bob] Shared key: $shared_key\n";
    while (my $data = <$cli_sock>)
    {
        #Now, the client will send a CBC encrypted message, and the IV
        #A->B
        #Send iv + AES-CBC(SHA1(s)[0:16], iv=random(16), msg)
        chomp($data);
        next unless length($data);
        #decode the data
        my $decoded  = decode_base64 $data;
        #The first 16 bytes will be the IV, the restant is the message
        my $IV = substr $decoded, 0, 16;
        my $cipher_msg = substr $decoded, 16;
        #decrypt the message
        my $plain_msg = AES_CBC::decrypt_data($cipher_msg, $shared_key, $IV, 1);
        #print the message to the screen
        print "[Bob] Received: $plain_msg\n";
        #now we send the same message back
        #B->A
        #Send iv + AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg)
        $cli_sock->send(
            encode_base64(
                $IV . AES_CBC::encrypt_data($plain_msg, $shared_key, $IV)
                ) . "\n"
            );
        $cli_sock->flush();
        print "[Bob] Message sent back.\n";
    }
    print "[Bob] Client disconnected.\n";
    print "-"x25 . "\n";
}