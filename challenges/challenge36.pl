use utf8;
use strict;
use bigint;
use threads;
use warnings;
use IO::Socket::INET;
use Digest::SHA qw( sha256 sha256_hex );
use lib ".";
use HMAC;

main() unless caller;

sub main
{
    #Again, without the network part, it would be so boring...
    my $th_server = threads->new(\&server_side);
    my $th_client = threads->new(\&client_side);
    $th_server->join();
    $th_client->join();
}

#Modular Exponetial function from Rosetta Code
#Avaiable at https://rosettacode.org/wiki/Modular_exponentiation#Perl
#Accessed in 18/feb/2020
sub expmod
{
    my($a, $b, $n) = @_;
    my $c = 1;
    do {
        ($c *= $a) %= $n if $b % 2;
        ($a *= $a) %= $n;
    } while ($b = int $b/2);
    $c;
}

sub server_side
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 12345;
    my $server = IO::Socket::INET->new(
        Listen      => 5,
        LocalAddr   => $host,
        LocalPort   => $port,
        Proto       => 'tcp'
    ) || die "Can't create socket server: $!";
    print "[Server] Listening on port $port\n";
    my ($g, $k, $N, $salt, $v);
    my $P = "HelloWorld!";
    while (1)
    {
        my $cli_sock = $server->accept();
        my $cli_host = $cli_sock->peerhost();
        my $cli_port = $cli_sock->peerport();
        print "[Server] Accepted connection from $cli_host:$cli_port\n";
        chomp(my $params = <$cli_sock>);
        ($g, $k) = (2, 3);
        $N       = $params;
        print "[Server] Received N=$N\n";
        $salt    = int rand $N;
        print "[Server] SALT: $salt\n";
        my $xH   = sha256_hex($salt . $P);
        my $x    = hex $xH;
        $v       = expmod($g, $x, $N);
        chomp($params = <$cli_sock>);
        my ($I, $A) = split /,/, $params;
        print "[Server] Received I=$I  and  A=$A\n";
        my $b    = int rand $N;
        my $B    = ($k * $v + expmod($g, $b, $N)) % $N;
        print "[Server] Sending SALT=$salt, B=$B\n";
        $cli_sock->send("$salt,$B\n");
        my $uH   = sha256_hex($A . $B);
        my $u    = hex($uH);
        my $S    = expmod($A * expmod($v, $u, $N), $b, $N);
        my $K    = sha256("$S");
        chomp(my $code = <$cli_sock>);
        print "[Server] Received HMAC=$code\n";
        my $hmac = HMAC::get_hmac(
            hash => \&sha256_hex,
            key  => $K,
            msg  => "$salt",
            bs   => 64
        );
        print "[Server] Calculated HMAC=$hmac\n";
        if ($code eq $hmac)
        {
            print "[Server] Client authenticated.\n";
            $cli_sock->send("OK");
        }
        else
        {
            print "[Server] Client not authenticated.\n";
            $cli_sock->send("INVALID!");
        }
    }
}

sub client_side
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 12345;
    my $client = IO::Socket::INET->new(
        PeerHost => $host,
        PeerPort => $port,
        Proto    => 'tcp'
    ) || die "Can't create socket client: $!";
    #As I didn't found a list of NIST approved primes, these are happy primes!
    #They are primes and they are happy (yeeey!!!)
    print "[Client] Connected to the server.\n";
    my @happy_primes = (
        103, 109, 139, 167, 193, 239, 263, 293, 313, 331, 367,
        379, 383, 397, 409, 487, 563, 617, 653, 673, 683, 709,
        739, 761, 863, 881, 907, 937, 1009, 1033, 1039, 1093
        );
    my ($g, $k) = (2, 3);
    my $N  = $happy_primes[int rand @happy_primes];
    print "[Client] Sending N=$N\n";
    $client->send("$N\n");
    my $a  = int rand $N;
    my $A  = expmod($g, $a, $N);
    my $I  = "lvmalware\@drk.com";
    my $P  = "HelloWorld!";
    print "[Client] Sending I=$I    and    A=$A\n";
    $client->send("$I,$A\n");
    chomp(my $params = <$client>);
    my ($salt, $B) = split /,/, $params;
    print "[Client] Received SALT=$salt    and     B=$B\n";
    my $uH = sha256_hex($A . $B);
    my $u  = hex($uH);
    my $xH = sha256_hex($salt . $P);
    my $x  = hex($xH);
    my $S  = expmod($B - $k * expmod($g, $x, $N), $a + $u * $x, $N);
    my $K  = sha256("$S");
    my $hmac = HMAC::get_hmac(
        hash => \&sha256_hex,
        key  => $K,
        msg  => "$salt",
        bs   => 64
    );
    print "[Client] Sending HMAC=$hmac\n";
    $client->send("$hmac\n");
    chomp(my $OK = <$client>);
    if ($OK eq 'OK')
    {
        print "[Client] Authentication successfull.\n"
    }
    else
    {
        print "[Client] Authentication failed.\n"
    }
}