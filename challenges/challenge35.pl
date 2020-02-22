use strict;
use threads;
use warnings;
use MIME::Base64;
use IO::Socket::INET;
use lib '.';
use DiffieHellman;
require "./utils.pl";
require "./challenge3.pl"; #for frequency analisys
require "./challenge10.pl";

my $th_attacker = threads->create(\&attacker_side);
my $th_server   = threads->create(\&server_side, '127.0.0.1', 12345);
my $th_client   = threads->create(\&client_side);

$th_attacker->join();
$th_server->join();
$th_client->join();

sub attacker_side
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 1234;
    my $server = IO::Socket::INET->new(
        Listen      => 5,
        LocalAddr   => $host,
        LocalPort   => $port,
        Proto       => 'tcp'
    ) || die "Error creating socket server: $!";

    #############################################################
    #                  Attack 1: G = A = 1                      #
    #############################################################
    print "[Attacker] Listening for connections on port $port...\n";
    #accept the incomming connection
    my $cli_sock = $server->accept();
    my $cli_addr = $cli_sock->peerhost();
    my $cli_port = $cli_sock->peerport();
    print "[Attacker] Accepted connection from $cli_addr:$cli_port\n";
    #create a socket connection with the true server
    my $serv_sock = IO::Socket::INET->new(
        PeerHost => shift || '127.0.0.1',
        PeerPort => shift || 12345,
        Proto    => 'tcp'
    ) || die "ERROR in Socket Creation : $!\n";
    #receive the first data from the client
    my $key_params = <$cli_sock>;
    #get the numbers P and G
    my ($p, $g) = split /,/, $key_params;
    print "[Attacker] Got: P=$p and G=$g\n";
    #send P and G=1 to the server
    $serv_sock->send("$p,1\n");
    print "[Attacker] Sent: P=$p and G=1\n";
    #receive the ACK packet
    my $ACK = <$serv_sock>;
    #send the ACK packet to the client
    $cli_sock->send($ACK);
    #get the A part of the key
    chomp(my $A = <$cli_sock>);
    print "[Attacker] Got: A=$A\n";
    #send 1 as the A part of the key to the server
    $serv_sock->send("1\n");
    print "[Attacker] Sent: A=1\n";
    #get the B  part of the key
    chomp(my $B = <$serv_sock>);
    print "[Attacker] Got: B=$B\n";
    #send the B part of the key to the client
    $cli_sock->send("$B\n");
    #with G=A=1, the server will caculate B as G^b % P = 1, since 1^b = 1
    #the client will calculate K as B^a % P = 1, since 1^a = 1
    #and the server will calculate K as A^b = 1, since 1^b = 1
    #so, both the client and the server will be using 1 as key
    my $K = Utils::derive_key(1);
    print "[Attacker] Shared key: $K\n";
    #now, we are able the decrypt the message. We just need to relay all the 
    #incoming messages to the server and to the client.
    chomp(my $received = <$cli_sock>);
    #decode the message
    my $decoded = decode_base64($received);
    #get the iv
    my $IV = substr $decoded, 0, 16;
    #get the encrypted message
    my $secret = substr $decoded, 16;
    #decrypt the message
    my $message = AES_CBC::decrypt_data($secret, $K, $IV, 1);
    print "[Attacker] Intercepted: $message\n";
    #relay the message to the server
    $serv_sock->send("$received\n");
    #get the server response
    my $response = <$serv_sock>;
    #relay to the client
    $cli_sock->send($response);
    print "[Attacker] Client disconnected.\n";
    $serv_sock->close();

    #############################################################
    #                   Attack 2: G = A = P                     #
    #############################################################

    print "[Attacker] Listening for connections on port $port...\n";
    #accept the incomming connection
    $cli_sock = $server->accept();
    $cli_addr = $cli_sock->peerhost();
    $cli_port = $cli_sock->peerport();
    print "[Attacker] Accepted connection from $cli_addr:$cli_port\n";
    #create a socket connection with the true server
    $serv_sock = IO::Socket::INET->new(
        PeerHost => shift || '127.0.0.1',
        PeerPort => shift || 12345,
        Proto    => 'tcp'
    ) || die "ERROR in Socket Creation : $!\n";
    #receive the first data from the client
    $key_params = <$cli_sock>;
    #get the numbers P and G
    ($p, $g) = split /,/, $key_params;
    print "[Attacker] Got: P=$p and G=$g\n";
    #send P and G=P to the server
    $serv_sock->send("$p,$p\n");
    print "[Attacker] Sent: P=$p and G=$p\n";
    #receive the ACK packet
    $ACK = <$serv_sock>;
    #send the ACK packet to the client
    $cli_sock->send($ACK);
    #get the A part of the key
    chomp($A = <$cli_sock>);
    print "[Attacker] Got: A=$A\n";
    #send P as the A part of the key to the server
    $serv_sock->send("$p\n");
    print "[Attacker] Sent: A=$p\n";
    #get the B  part of the key
    chomp($B = <$serv_sock>);
    print "[Attacker] Got: B=$B\n";
    #send the B part of the key to the client
    $cli_sock->send("$B\n");
    #with G=A=P, the server will caculate B as G^b % P = 0, since P^b % P = 0
    #the client will calculate K as B^a % P = 0, since 0^a = 1
    #and the server will calculate K as A^b % P = 0, since P^b % P = 1
    #so, both the client and the server will be using 0 as key
    $K = Utils::derive_key(0);
    print "[Attacker] Shared key: $K\n";
    #now, we are able the decrypt the message. We just need to relay all the 
    #incoming messages to the server and to the client.
    chomp($received = <$cli_sock>);
    #decode the message
    $decoded = decode_base64($received);
    #get the iv
    $IV = substr $decoded, 0, 16;
    #get the encrypted message
    $secret = substr $decoded, 16;
    #decrypt the message
    $message = AES_CBC::decrypt_data($secret, $K, $IV, 1);
    print "[Attacker] Intercepted: $message\n";
    #relay the message to the server
    $serv_sock->send("$received\n");
    #get the server response
    $response = <$serv_sock>;
    #relay to the client
    $cli_sock->send($response);
    print "[Attacker] Client disconnected.\n";
    $serv_sock->close();

    #############################################################
    #                   Attack 3: G = A = P-1                   #
    #############################################################

    print "[Attacker] Listening for connections on port $port...\n";
    #accept the incomming connection
    $cli_sock = $server->accept();
    $cli_addr = $cli_sock->peerhost();
    $cli_port = $cli_sock->peerport();
    print "[Attacker] Accepted connection from $cli_addr:$cli_port\n";
    #create a socket connection with the true server
    $serv_sock = IO::Socket::INET->new(
        PeerHost => shift || '127.0.0.1',
        PeerPort => shift || 12345,
        Proto    => 'tcp'
    ) || die "ERROR in Socket Creation : $!\n";
    #receive the first data from the client
    $key_params = <$cli_sock>;
    #get the numbers P and G
    ($p, $g) = split /,/, $key_params;
    print "[Attacker] Got: P=$p and G=$g\n";
    #send P and G=P-1 to the server
    $serv_sock->send("$p," . ($p-1) ."\n");
    print "[Attacker] Sent: P=$p and G=" . ($p-1) . "\n";
    #receive the ACK packet
    $ACK = <$serv_sock>;
    #send the ACK packet to the client
    $cli_sock->send($ACK);
    #get the A part of the key
    chomp($A = <$cli_sock>);
    print "[Attacker] Got: A=$A\n";
    #send P-1 as the A part of the key to the server
    $serv_sock->send(($p - 1) . "\n");
    print "[Attacker] Sent: A=" . ($p - 1) ."\n";
    #get the B  part of the key
    chomp($B = <$serv_sock>);
    print "[Attacker] Got: B=$B\n";
    #send the B part of the key to the client
    $cli_sock->send("$B\n");
    #the client will calculate K as B^a % P = +-1
    #and the server will calculate K as A^b %P = +-1
    #so, both the client and the server will be using +-1 as key
    #we just need to figure out if it's +1 or -1. Let's try both and see which
    #one produces a english-like text
    my $K1 = Utils::derive_key(1);
    my $K2 = Utils::derive_key(-1);
    chomp($received = <$cli_sock>);
    #decode the message
    $decoded = decode_base64($received);
    #get the iv
    $IV = substr $decoded, 0, 16;
    #get the encrypted message
    $secret = substr $decoded, 16;
    #decrypt the message
    my $x = AES_CBC::decrypt_data($secret, $K1, $IV, 1);
    my $y = AES_CBC::decrypt_data($secret, $K2, $IV, 1);
    print "Y: $y           X: $x\n";
    $K = XorUtils::freq_analysis($x) > XorUtils::freq_analysis($y) ? $K1 : $K2;
    print "[Attacker] Shared key (client): $K\n";
    $message = AES_CBC::decrypt_data($secret, $K, $IV, 1);
    print "[Attacker] Intercepted: $message\n";
    #relay the message to the server
    $serv_sock->send("$received\n");
    #get the server response
    $response = <$serv_sock>;
    #relay to the client
    $cli_sock->send($response);
    print "[Attacker] Client disconnected.\n";
    $serv_sock->close();

}

sub server_side
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 1234;
    my $server = IO::Socket::INET->new(
        Listen      => 5,
        LocalAddr   => $host,
        LocalPort   => $port,
        Proto       => 'tcp'
    ) || die "Error creating socket server: $!";
    while (1)
    {
        print "[Server] Listening for connections on port $port...\n";
        my $cli_sock = $server->accept();
        my $cli_addr = $cli_sock->peerhost();
        my $cli_port = $cli_sock->peerport();
        print "[Server] Accepted connection from $cli_addr:$cli_port\n";
        my $data = <$cli_sock>;
        chomp($data);
        #get the numbers P and G
        my ($p, $g) = split /,/, $data;
        #initialize a new DiffieHellman object
        my $bob = DiffieHellman->new(p => $p, g => $g);
        #acknowledge
        $cli_sock->send("ACK\n"); #"ACK" packet :p
        #get the A part of the key
        chomp(my $A = <$cli_sock>);
        #calculate and send the B part of the key
        my $B = $bob->get_public_key();
        $cli_sock->send("$B\n");
        #calculate the shared key
        my $K = Utils::derive_key($bob->get_shared_secret_key($A));
        print "[Server] Shared Key: $K\n";
        #receive the message from the client
        my $received = <$cli_sock>;
        #decode the message
        my $decoded = decode_base64 $received;
        #get the first 16 bytes as IV
        my $IV = substr $decoded, 0, 16;
        #get the encrypted message
        my $secret = substr $decoded, 16;
        #decrypt the message
        my $msg = AES_CBC::decrypt_data($secret, $K, $IV, 1);
        print "[Server] Received: $msg\n";
        #reencrypt with the shared key
        $secret = encode_base64($IV . AES_CBC::encrypt_data($msg, $K, $IV));
        #send the message back
        $cli_sock->send("$secret\n");
        print "[Server] Client disconnected.\n";
    }

}

sub client_side
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 1234;
    for my $c (1 .. 3)
    {
        print "="x80 . "\n";
        my $client = IO::Socket::INET->new(
            PeerHost    => $host,
            PeerPort    => $port,
            Proto       => 'tcp'
        ) || die ("Failed to create the socket connection: $!");
        print "[Client] Connected to $host:$port.\n";

        my ($p, $g) = (457, 3);
        #create a new DiffieHellman object
        my $alice = DiffieHellman->new( p => $p, g => $g);
        #calculate the A part of the message
        my $A = $alice->get_public_key();
        #send the numbers P and G
        $client->send("$p,$g\n");
        #receive the ACK packet
        <$client>; #ACK
        #send the A part of the key
        $client->send("$A\n");
        #receive the V part of the key
        chomp(my $B = <$client>);
        #calculate the secret key
        my $K = Utils::derive_key($alice->get_shared_secret_key($B));
        print "[Client] Shared Key: $K\n";
        #generate a random IV
        my $IV = Utils::random_bytes(16);
        my $message = "Hello, World!";
        #encode the IV and the encrypted message as Base64
        my $secret = encode_base64($IV . AES_CBC::encrypt_data($message, $K, $IV));
        #send the message
        $client->send("$secret\n");
        print "[Client] Sent message.\n";
        #receive the response from the server
        chomp(my $response = <$client>);
        #decode the response
        my $decoded = decode_base64 $response;
        #get the first 16 bytes as IV
        $IV = substr $decoded, 16;
        #get the encrypted message
        $secret = substr $decoded, 16;
        #decrypt the message
        my $msg = AES_CBC::decrypt_data($secret, $K, $IV, 1);
        print "[Client] Received: $msg\n";
        $client->close();
    }
}
