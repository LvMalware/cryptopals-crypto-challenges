package MT19937;
use utf8;
use strict;
use warnings;

use constant {
    W => 32,
    N => 624,
    M => 397,
    R => 31,
    A => 0x9908B0DF,
    U => 11,
    D => 0xFFFFFFFF,
    S => 7,
    B => 0x9D2C5680,
    T => 15,
    C => 0xEFC60000,
    L => 18,
    F => 1812433253
};

use constant LOWER_MASK => (1 << R) - 1;
use constant UPPER_MASK => ((1 << W) - 1) & ~LOWER_MASK;

my @MT = map { 0 } 1 .. N;
my $index = N + 1;

sub lowest_w_bits { ((1 << W) - 1) & shift }

sub seed_mt
{
    $index = N;
    $MT[0] = shift;
    for my $i (1 .. N - 1)
    {
        $MT[$i] = lowest_w_bits(F * ($MT[$i-1] ^ ($MT[$i-1] >> (W-2))) + $i);
    }
}

sub twist
{
    for my $i (0 .. N - 1)
    {
        my $x   = ($MT[$i] & UPPER_MASK) + ($MT[($i + 1) % N] & LOWER_MASK);
        my $xA  = $x >> 1;
        $xA     = $xA ^ A if ($x % 2);
        $MT[$i] = $MT[($i + M) % N] ^ $xA;
    }
    $index = 0;
}

sub extract_number
{
    if ($index >= N)
    {
        die ("Generator was never seeded.") if ($index > N);
        twist;
    }
    my $y = $MT[$index];
    $y   ^= (($y >> U) & D);
    $y   ^= (($y << S) & B);
    $y   ^= (($y << T) & C);
    $y   ^= ($y >> L);
    $index++;
    lowest_w_bits $y
}

sub rnd { extract_number() % shift }

sub test
{
    seed_mt time;
    for my $x (0 .. 10)
    {
        print "$x\t:\t" . extract_number . "\n";
    }
}

test unless caller;