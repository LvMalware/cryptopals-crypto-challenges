package PKCS1_ATK;
use utf8;
use bigint;
use strict;
use warnings;
use Digest::SHA qw(sha1);
use ntheory qw(invmod powmod);
use Math::BigInt::Random qw(random_bigint);
use lib '.';
eval 'use RSA';
require "./utils.pl";

my $rsa;
#changes for challenge 48 (Yeah, I know... it's not a very elegant solution)
sub new_rsa { $rsa = RSA->new(key_len => $_[0]) }
sub get_rsa { $rsa }

sub PKCS_encode
{
    "\x00\x02" . Utils::random_bytes($_[1] - 3 - length($_[0])) . "\x00$_[0]"
}

sub PKCS_conforming
{
    RSA::_int_str(powmod($_[0], $rsa->{d}, $rsa->{n})) =~ /^\x02/;
}

sub max { $_[0] > $_[1] ? $_[0] : $_[1] }

sub min { $_[0] > $_[1] ? $_[1] : $_[0] }

sub add_interval
{
    my ($m, $l, $u) = @_;
    for (my $i = 0; $i < @{$m}; $i++)
    {
        my ($a, $b) = @{$m->[$i]};
        unless (($b < $l) || ($a > $u))
        {
            my ($a1, $b1) = (min($l, $a), max($u, $b));
            $m->[$i] = [$a1, $b1];
            return
        }
    }
    push @$m, [$l, $u];
}

sub PKCS_conforming_attack
{
    my ($c, $k)     = @_;
    my ($n, $e, $i) = ($rsa->{n}, $rsa->{e}, 1);
    my $c0          = $c;
    my $B           = 2 ** (8 * ($k - 2));
    my @M           = ([2 * $B, 3 * $B - 1]);
    my $s           = 1;

    until (PKCS_conforming($c0))
    {
        #print "Step 1\n";
        $s = random_bigint(min => 1, max => $n);
        $c0 = ($c * powmod($s, $e, $n)) % $n;
    }

    while (1)
    {
        #print "Iteration $i\n";
        if ($i == 1)
        {
            #print "Step 2.a\n";
            $s = div_ceil($n, 3 * $B);
            while (1)
            {
                $c = ($c0 * powmod($s, $e, $n)) % $n;
                last if PKCS_conforming($c);
                $s ++;
            }
        }
        elsif (@M >= 2)
        {
            #print "Step 2.b\n";
            while (1)
            {
                $s ++;
                $c = ($c0 * powmod($s, $e, $n)) % $n;
                last if PKCS_conforming($c);
            }
        }
        elsif (@M == 1)
        {
            #print "Step 2.c\n";
            my ($a, $b) = @{$M[0]};
            return RSA::_int_str($a) if ($a == $b);
            my $r = div_ceil(2 * ($b * $s - 2 * $B), $n);
            $s = div_ceil(2 * $B + $r * $n, $b);
            while (1)
            {
                $c = ($c0 * powmod($s, $e, $n)) % $n;
                last if PKCS_conforming($c);
                $s ++;
                if ($s > int((3 * $B + $r * $n) / $a))
                {
                    $r ++;
                    $s = div_ceil(2 * $B + $r * $n, $b);
                }
            }
        }

        #print "Step 3\n";
        my @intervals;

        for my $ab (@M)
        {
            my ($a, $b) = @{$ab};
            my $r0 = div_ceil($a * $s - 3 * $B + 1, $n);
            my $r1 = int(($b * $s - 2 * $B) / $n);

            for (my $r = $r0; $r <= $r1; $r ++)
            {
                my $lower = max($a, div_ceil(2 * $B + $r * $n, $s));
                my $upper = min($b, int((3 * $B - 1 + $r * $n) / $s));
                die "Unexpected: L=$lower > U=$upper" if ($lower > $upper);
                add_interval \@intervals, $lower, $upper;
            }
        }
        die "No valid intervals found (try again)" unless (@intervals > 0);
        @M = @intervals;
        $i ++;
    }
}

sub div_ceil { int(($_[0] + $_[1] - 1) / $_[1]) }

sub test
{
    new_rsa(256);
    my $m = "kick it, CC";
    my $c = $rsa->encrypt(PKCS_encode($m, $rsa->{key_len} / 8));
    if (PKCS_conforming($c))
    {
        print "PKCS1.5 - OK\n"
    }
    else
    {
        die "Something is wrong with my PKCS1.5 implementation?"
    }
    print "This may take a while...\n";
    my $dec = PKCS_conforming_attack $c, 32;
    print "-"x80 . "\n";
    print "DEC: $dec\n";
}

test unless caller;
