use utf8;
use strict;
use warnings;
require "./challenge22.pl";

#Here I'm gonna need to make a little kludge. Since I didn't implemented the
#MT19937 RNG as a class (object oriented), I will need to reimplement all of its
#functions to simulate a "clone" of the RNG... so, let's go

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
    $index = $index + 1;
    lowest_w_bits $y
}

#untemper functions

sub get_bit
{
    my ($number, $position) = @_;
    return 0 if (($position > 31) || ($position < 0));
    ($number >> (31 - $position)) & 1
}

sub set_bit
{
    my ($number, $position) = @_;
    $number | (1 << (31 - $position))
}

sub right_undo
{
    my ($number, $count) = @_;
    my $unshifted = 0;
    for my $i (0 .. 31)
    {
        my $bit = get_bit($number, $i) ^ get_bit ($unshifted, $i - $count);
        $unshifted = set_bit($unshifted, $i) if $bit;
    }
    $unshifted;
}

sub left_undo
{
    #thanks Wikipedia

    my ($number, $count, $and) = @_;
    my $unshifted = 0;
    for my $i (0 .. 31)
    {
        my $bit = get_bit($number, 31 - $i) ^ (
                  get_bit($unshifted, 31 - ($i - $count)) &
                  get_bit($and, 31 - $i)
                );
        $unshifted = set_bit($unshifted, 31 - $i) if $bit;
    }
    $unshifted;
}

sub untemper
{
    my $y = shift;
    $y = right_undo $y, L;
    $y = left_undo $y, T, C;
    $y = left_undo $y, S, B;
    $y = right_undo $y, U;
    $y
}

sub clone_mt19937
{
    seed_mt 0;
    for my $i (1 .. N)
    {
        $MT[$i - 1] = untemper(MT19937::extract_number());
    }
}

sub main
{
    MT19937::seed_mt(time);
    clone_mt19937;
    for my $x (1 .. 100)
    {
        my ($original, $cloned) = (MT19937::extract_number(), extract_number());
        if ($original == $cloned)
        {
            print "Test #$x: All right!\n";
        }
        else
        {
            die "Test $x: $cloned not equal to $original";
        }
    }
}

main unless caller;