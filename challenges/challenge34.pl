use utf8;
use strict;
use warnings;
use MIME::Base64;
use IO::Socket::INET;
use Digest::SHA qw( sha1_hex );
use lib ".";
use DiffieHellman;
require "./utils.pl";
require "./challenge10.pl";

#First, start the attacker (this one) with: perl challenge34.pl
#Then, start the server (Bob) with: perl bob.pl
#And finally, start the client (Alice) with: perl alice.pl

#Now, just watch as the attack is being performed

#Note: This was the way I found to carry out this attack, simulating the client,
#server and attacker machines, all on the same computer and without a virtual 
#machine. I know I could have done it without the network part, but it would 
#have been very boring. So here we go...

MITM() unless caller;

sub MITM
{
    #Man In The Middle (the attack, not that music of The Bee Gees)

    #Bind to the port 2019, so the server (Bob) will choose the port 2020
    my $port = 2019;
    my $addr = '127.0.0.1';
    my $sock = IO::Socket::INET->new(Listen    => 5,
                                     LocalAddr => $addr,
                                     LocalPort => $port,
                                     Proto     => 'tcp');
    print "[Attacker] Server listening for connections on port $port\n";
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
        print "[Attacker] Accepted connection from $cli_addr:$cli_port\n";
        #Only one client at time... as I said, not ideal
        handle_client($cli_sock);
    }
}

sub handle_client
{
    my $cli_sock = shift;
    #Start a connection with the real server
    my $bob_sock = new IO::Socket::INET(PeerHost => shift || '127.0.0.1',
                                      PeerPort => shift || 2020,
                                      Proto    => 'tcp') ||
                    die ("[Attacker] Error connecting to the server: $!");
    print "[Attacker] connected to the real server";
    #First, the client will send the needed data for a key exchange
    #A->M
    #Send "p", "g", "A"
    chomp(my $key_exchange_params = <$cli_sock>);
    #the numbers p, g and A will be sepparated by a ','
    my ($p, $g, $A) = split /,/, $key_exchange_params;
    print "[Attacker] Got P: $p\n";
    print "[Attacker] Got G: $g\n";
    print "[Attacker] Got A: $A\n";
    #Now we send a modified version of it to the server
    #M->B
    #Send "p", "g", "p"
    $bob_sock->send("$p,$g,$p\n");
    #then we get the servers part of the key
    #B->M
    #Send "B"
    chomp(my $B = <$bob_sock>);
    #and send a different one to the client
    #M->A
    #Send "p"
    $cli_sock->send("$p\n");
    #Now we get a message from the client
    #A->M
    #Send iv + AES-CBC(SHA1(s)[0:16], iv=random(16), msg)
    my $received = <$cli_sock>;
    #and send the same message to the server
    #M->B
    #Relay that to B
    $bob_sock->send($received);
    #the server will then send the message back
    #B->M
    #Send iv + AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg)
    my $replyed = <$bob_sock>;
    #And we send it to the client
    #M->A
    #Relay that to A
    $cli_sock->send($replyed);
    #now the connection is over. Let's decrypt the message
    #If it all happened the right way. The shared key must be equal to 0, so the
    #derived key will be sha1('0')
    my $shared_key  = substr sha1_hex('0'), 0, 16;
    my $decoded_msg = decode_base64($received);
    my $IV          = substr $decoded_msg, 0, 16;
    my $cipher_msg  = substr $decoded_msg, 16;
    #so we can decrypt the message easily
    my $plain_msg   = AES_CBC::decrypt_data($cipher_msg, $shared_key, $IV, 1);
    print "[Attacker] Decrypted message: $plain_msg\n";
    print "-"x25 . "\n";
}