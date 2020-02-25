use utf8;
use strict;
use threads;
use warnings;
use IO::Socket::INET;
use Digest::SHA qw(sha256 sha256_hex);
require "./challenge36.pl";

sub srp_attak
{
    my $host = shift || '127.0.0.1';
    my $port = shift || 12345;
    my @happy_primes = (
        103, 109, 139, 167, 193, 239, 263, 293, 313, 331, 367,
        379, 383, 397, 409, 487, 563, 617, 653, 673, 683, 709,
        739, 761, 863, 881, 907, 937, 1009, 1033, 1039, 1093
        );
    my ($g, $k) = (2, 3);
    my $N  = $happy_primes[int rand @happy_primes];

    for my $A (0, $N, 2*$N)
    {
        my $client = IO::Socket::INET->new(
            PeerHost => $host,
            PeerPort => $port,
            Proto    => 'tcp'
        ) || die "Can't create socket client: $!";
        print "\n" . "="x80 . "\n\n";
        print "[Client] Connected to the server.\n";
        print "[Client] Sending N=$N\n";
        $client->send("$N\n");

        my $I  = "lvmalware\@drk.com";
        my $P  = "Any Password will fit";

        print "[Client] Sending I=$I    and    A=$A\n";
        $client->send("$I,$A\n");
        chomp(my $params = <$client>);
        my ($salt, $B) = split /,/, $params;
        print "[Client] Received SALT=$salt    and     B=$B\n";
        #Sending A = 0, N or 2*N will produce S = 0 on the server side
        my $S  = 0;
        my $K  = sha256("$S");
        #With S = 0, we can log in with any password we send
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
}

sub test
{
    my $th_server = threads->new(\&SRP::server_side);
    my $th_attack = threads->new(\&srp_attak);
    $th_server->join();
    $th_attack->join();
}

test unless caller;