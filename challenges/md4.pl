package MD4;
use utf8;
use strict;
use warnings;
use Digest::MD4 qw ( md4_hex ); #just for validation.

#NOTE: This is a pure-Perl implementation of the MD4 Hashing algorithm,
#implement by Lucas V. Araujo (LvMalware on GitHub), following the instructions
#of the RFC 1320, avaiable at <http://www.faqs.org/rfcs/rfc1320.html>.

sub new
{
    my $self = shift;
    bless {}, $self;
}

sub md_pad
{
    my $message = shift;
    my $length  = shift || length($message) * 8;
    $message   .= "\x80";
    $message   .= "\x00" while ((8 + length($message)) % 64) != 0;
    $message . pack("Q<", $length);
}
#ROUND LEFT ROTATION
sub __LF { (($_[0] << $_[1]) & 0xffffffff) | ($_[0] >> (32 - $_[1])) }

#F(X,Y,Z) = XY v not(X) Z
sub __F { ($_[0] & $_[1]) | ((~$_[0]) & $_[2]) }

#G(X,Y,Z) = XY v XZ v YZ
sub __G { ($_[0] & $_[1]) | ($_[0] & $_[2]) | ($_[1] & $_[2]) }

#H(X,Y,Z) = X xor Y xor Z
sub __H { $_[0] ^ $_[1] ^ $_[2]  }

sub get_digest
{
    my $self    = shift;
    my $message = shift;
    my $length  = shift || length($message) * 8;
    my $A       = shift || 0x67452301;
    my $B       = shift || 0xefcdab89;
    my $C       = shift || 0x98badcfe;
    my $D       = shift || 0x10325476;
    
    $message    = md_pad $message, $length;

    for (my $i = 0; $i < length($message); $i += 64)
    {
        #COPY THE BLOCK i TO X

        my @X = unpack "V16", substr($message, $i, 64);

        #SAVE THE VALUES A, B, C, D

        my ($AA, $BB, $CC, $DD) = ($A, $B, $C, $D);
        
        #ROUND 1

        for my $j (0 .. 15)
        {
            if ($j % 4 == 0)
            {
                $A = __LF(($A + __F($B, $C, $D) + $X[$j]) & 0xffffffff, 3)
            }
            elsif ($j % 4 == 1)
            {
                $D = __LF(($D + __F($A, $B, $C) + $X[$j]) & 0xffffffff, 7)
            }
            elsif ($j % 4 == 2)
            {
                $C = __LF(($C + __F($D, $A, $B) + $X[$j]) & 0xffffffff, 11)
            }
            elsif ($j % 4 == 3)
            {
                $B = __LF(($B + __F($C, $D, $A) + $X[$j]) & 0xffffffff, 19)
            }
        }

        #ROUND 2

        for my $j (0 .. 15)
        {
            my $k = int($j / 4) + ($j % 4) * 4;
            if ($j % 4 == 0)
            {
                $A = __LF(
                    ($A + __G($B, $C, $D) + $X[$k] + 0x5a827999) & 0xffffffff,
                    3)
            }
            elsif ($j % 4 == 1)
            {
                $D = __LF(
                    ($D + __G($A, $B, $C) + $X[$k] + 0x5a827999) & 0xffffffff,
                    5)
            }
            elsif ($j % 4 == 2)
            {
                $C = __LF(
                    ($C + __G($D, $A, $B) + $X[$k] + 0x5a827999) & 0xffffffff, 
                    9)
            }
            elsif ($j % 4 == 3)
            {
                $B = __LF(
                    ($B + __G($C, $D, $A) + $X[$k] + 0x5a827999) & 0xffffffff,
                    13)
            }
        }

        #ROUND 3

        my @order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15);
        for my $j (0 .. 15)
        {
            my $k = $order[$j];
            if ($j % 4 == 0)
            {
                $A = __LF(
                    ($A + __H($B, $C, $D) + $X[$k] + 0x6ed9eba1) & 0xffffffff,
                    3)
            }
            elsif ($j % 4 == 1)
            {
                $D = __LF(
                    ($D + __H($A, $B, $C) + $X[$k] + 0x6ed9eba1) & 0xffffffff,
                    9)
            }
            elsif ($j % 4 == 2)
            {
                $C = __LF(
                    ($C + __H($D, $A, $B) + $X[$k] + 0x6ed9eba1) & 0xffffffff,
                    11)
            }
            elsif ($j % 4 == 3)
            {
                $B = __LF(
                    ($B + __H($C, $D, $A) + $X[$k] + 0x6ed9eba1) & 0xffffffff,
                    15)
            }
        }

        #ADD THE PREVIOUS VALUES

        $A = ($A + $AA) & 0xffffffff;
        $B = ($B + $BB) & 0xffffffff;
        $C = ($C + $CC) & 0xffffffff;
        $D = ($D + $DD) & 0xffffffff;
    }
    unpack "H*", pack("V4", ($A, $B, $C, $D))
}

sub get_mac { get_digest shift, join '', @_ }

sub test
{
    my $test_str = "Hello, World!";
    my $lib_md4  = md4_hex $test_str;
    my $my_md4   = MD4->new()->get_digest($test_str);
    print "Digest::MD4 : $lib_md4\n";
    print "My MD4      : $my_md4\n";
    if ($my_md4 eq $lib_md4)
    {
        print "MD4 Working!\n"
    }
    else
    {
        die "My MD4 function is a failure :("
    }

}

test unless caller;