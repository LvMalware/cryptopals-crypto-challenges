package s_SRP; #simplified SRP
use utf8;
use strict;
use bigint;
use threads;
use warnings;
use IO::Socket::INET;
use Digest::SHA qw(sha256 sha256_hex);
use Math::BigInt::Random qw(random_bigint);
require "./utils.pl";
use lib ".";
use HMAC;

my @happy_primes = (
    103, 109, 139, 167, 193, 239, 263, 293, 313, 331, 367,
    379, 383, 397, 409, 487, 563, 617, 653, 673, 683, 709,
    739, 761, 863, 881, 907, 937, 1009, 1033, 1039, 1093
);

my $N = $happy_primes[int rand @happy_primes];
my ($g, $k) = (2, 3);
#chooses a random word from /usr/share/dict/words as password
my $P = Utils::choose_key();

sub server_side
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 12345;
    my $server = IO::Socket::INET->new(
        Listen      => 5,
        LocalAddr   => $host,
        LocalPort   => $port,
        Proto       => 'tcp'
    ) || die "$0: can't create socket server: $!";
    print "[Server] Listening for connections on port $port\n";
    while (my $client = $server->accept())
    {
        my $cli_addr = $client->peerhost();
        my $cli_port = $client->peerport();
        print "[Server] Accepted connection from $cli_addr:$cli_port\n";
        my $salt = int rand $N;
        my $x = hex(sha256_hex($salt . $P));
        my $v = Utils::expmod($g, $x, $N);
        chomp(my $params = <$client>);
        my ($I, $A) = split /,/, $params;
        print "[Server] Received I=$I, A=$A\n";
        my $b = int(rand($N));
        my $B = Utils::expmod($g, $b, $N);
        my $u = random_bigint(length_bin => 1, length => 128);
        $client->send("$salt,$B,$u\n");
        print "[Server] Sent SALT=$salt, B=$B, u=$u\n";
        my $S = Utils::expmod($A * Utils::expmod($v, $u, $N), $b, $N);
        my $K = sha256("$S");
        my $hmac = HMAC::get_hmac(
            hash => \&sha256_hex,
            key  => $K,
            msg  => "$salt",
            bs   => 64
        );
        print "[Server] Calculated HMAC=$hmac\n";
        chomp(my $code = <$client>);
        if ($code eq $hmac)
        {
            $client->send("OK\n");
            print "[Server] Client authenticated.\n";
        }
        else
        {
            $client->send("ERROR");
            print "[Server] Client not authenticated.\n";
        }
    }
}

sub man_in_the_middle
{

    my $host = shift || '127.0.0.1';
    my $port = shift || 1234;
    my $mitm = IO::Socket::INET->new(
        Listen      => 5,
        LocalAddr   => $host,
        LocalPort   => $port,
        Proto       => 'tcp'
    ) || die "$0: can't create socket server: $!";
    print "[Attacker] Listening for connections on port $port\n";
    my $client = $mitm->accept();
    my $cli_addr = $client->peerhost();
    my $cli_port = $client->peerport();
    print "[Attacker] Accepted connection from $cli_addr:$cli_port\n";
    my $server = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => 12345,
        Proto    => 'tcp'
    ) || die "$0: can't connect to the server: $!";
    print "[Attacker] Connected to the real server\n";
    chomp(my $params = <$client>);
    my ($I, $A) = split /,/, $params;
    print "[Attacker] Intercepted: I=$I, A=$A\n";
    $server->send("$params\n");
    chomp($params = <$server>);
    my ($salt, $B, $u) = split /,/, $params;
    my $b = int rand $N;
    my $mB = Utils::expmod($g, $b, $N);
    print "[Attacker] Intercepted: SALT=$salt, B=$B, u=$u\n";
    $client->send("$salt,$mB,$u\n");
    chomp(my $cli_hmac = <$client>);
    print "[Attacker] Intercepted: HMAC=$cli_hmac\n";
    $server->send("$cli_hmac\n");
    chomp(my $resp = <$server>);
    print "[Attacker] Intercepted: status=$resp\n";
    $client->send("$resp\n");
    sleep(1);
    #now we can try a brute force on the password!
    print "[Attacker] Starting brute force process...\n";
    open my $file, "< :encoding(UTF-8)", "/usr/share/dict/words";
    while (my $password = <$file>)
    {
        chomp($password);
        print "[Attacker] Trying password: $password\n";
        my $x = hex(sha256_hex($salt . $password));
        my $v = Utils::expmod($g, $x, $N);
        my $S = Utils::expmod($A * Utils::expmod($v, $u, $N), $b, $N);
        my $K = sha256("$S");
        my $hmac = HMAC::get_hmac(
            hash => \&sha256_hex,
            key  => $K,
            msg  => "$salt",
            bs   => 64
        );
        if ($hmac eq $cli_hmac)
        {
            print "="x80 . "\n";
            print "[Attacker] Found password: $password\n";
            last;
        }
    }
    close($file);
}

sub client_side
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 1234; #MITM port
    my $tryes = shift || 1;
    for my $test (1 .. $tryes)
    {
        print "\n" . "="x80 . "\n";
        my $client = IO::Socket::INET->new(
            PeerHost   => $host,
            PeerPort   => $port,
            Proto      => 'tcp'
        ) || die "$0: can't create socket client: $!";
        print "[Client] Connected to $host:$port\n";
        my $a = int(rand($N));
        my $A = Utils::expmod($g, $a, $N);
        $client->send("lv\@malware.drk,$A\n");
        print "[Client] Sent I=lv\@malware.drk, A=$A\n";
        chomp(my $params = <$client>);
        my ($salt, $B, $u) = split /,/, $params;
        my $x = hex(sha256_hex($salt . $P));
        my $S = Utils::expmod($B, $a + $u*$x, $N);
        my $K = sha256("$S");
        my $hmac = HMAC::get_hmac(
            hash => \&sha256_hex,
            key  => $K,
            msg  => "$salt",
            bs   => 64
        );
        print "[Client] Calculated HMAC=$hmac\n";
        $client->send("$hmac\n");
        chomp(my $success = <$client>);
        if ($success eq "OK")
        {
            print "[Client] Authentication successfull.\n";
        }
        else
        {
            print "[Client] Authentication failed.\n";
        }
        sleep(1);
    }
}

my $th_server = threads->new(\&server_side);
my $th_mitm   = threads->new(\&man_in_the_middle);
my $th_client = threads->new(\&client_side);
$th_server->join();
$th_mitm->join();
$th_client->join();