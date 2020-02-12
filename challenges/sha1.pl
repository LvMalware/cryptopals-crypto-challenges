package SHA1;
use utf8;
use strict;
use warnings;
use Digest::SHA1 qw ( sha1_hex ); #just for testing...

sub new
{
    my $self = shift;
    bless {}, $self
}

sub __left_rotate { (($_[0] << $_[1]) & 0xffffffff) | ($_[0] >> (32 - $_[1])) }

sub sha1_sum
{
    my $self    = shift;
    my $message = shift;
    my $length  = shift || length($message)*8;
    my ($h0, $h1, $h2, $h3, $h4) = @_ ||
       (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0);
    $message .= "\x80";
    $message .= "\x00" while (((8 * length($message)) % 512)) != 448;
    $message .= pack("Q>", $length);
    for (my $i = 0; $i < length($message); $i += 64)
    {
        my @w = map { 0 } 1 .. 80;
        $w[$_] = unpack("I>", substr($message, $i + $_ * 4, 4)) for 0 .. 15;
        $w[$_] = __left_rotate($w[$_ - 3] ^ $w[$_ - 8] ^
                               $w[$_ - 14] ^ $w[$_ - 16], 1) for 16 .. 79;
        my ($a, $b, $c, $d, $e) = ($h0, $h1, $h2, $h3, $h4);
        my $f;
        my $k;
        for my $j ( 0 .. 79 )
        {
            if ($j <= 19)
            {
                $f = ($b & $c) | (~$b & $d);
                $k = 0x5A827999;
            }
            elsif ($j <= 39)
            {
                $f = $b ^ $c ^ $d;
                $k = 0x6ED9EBA1;
            }
            elsif ($j <= 59)
            {
                $f = ($b & $c) | ($d & ($b | $c));
                $k = 0x8F1BBCDC;
            }
            else
            {
                $f = $b ^ $c ^ $d;
                $k = 0xCA62C1D6;
            }
            my $tmp = __left_rotate($a, 5) + $f + $e + $k + $w[$j] & 0xffffffff;
            ($e, $d, $c, $b, $a) = ($d, $c, __left_rotate($b, 30), $a, $tmp);
        }
        $h0 = ($h0 + $a) & 0xffffffff;
        $h1 = ($h1 + $b) & 0xffffffff;
        $h2 = ($h2 + $c) & 0xffffffff;
        $h3 = ($h3 + $d) & 0xffffffff;
        $h4 = ($h4 + $e) & 0xffffffff;
    }
    sprintf("%08x%08x%08x%08x%08x", $h0, $h1, $h2, $h3, $h4);
}

sub sha1_mac { sha1_sum shift, join '', @_ }

sub test
{
    my $sha = SHA1->new();
    print $sha->sha1_sum("test") . "\n";
    print sha1_hex("test") . "\n";
}
test unless caller;