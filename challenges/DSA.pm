package DSA;
use strict;
use bigint;
use warnings;
use base 'Exporter';
use ntheory qw(invmod);
use Math::BigInt::Random;

our $VERSION = 0.1;
our @EXPORT  = qw (dsa_sign dsa_verify);

sub new
{
    my $self = shift;
    my %args = @_;
    my $data = {
        g => $args{g},
        h => $args{h},
        p => $args{p},
        q => $args{q},
    };
    $data->{x} = random_bigint(min => 1, max => $data->{q});
    $data->{y} = expmod($data->{g}, $data->{x}, $data->{p});
    bless $data, $self;
}

sub sign {
    dsa_sign($_[0]->{g}, $_[0]->{h}, $_[1], $_[0]->{p}, $_[0]->{q}, $_[0]->{x})
}

sub verify
{
    dsa_verify(
        $_[1], $_[2], $_[0]->{h}, $_[3], $_[0]->{p},
        $_[0]->{q}, $_[0]->{g}, $_[0]->{y}
    )
}

sub dsa_sign
{
    my ($g, $h, $m, $p, $q, $x) = @_;
    my ($s, $r) = (0, 0);
    while (($r == 0) || ($s == 0))
    {
        my $k = random_bigint(min => 1, max => $q);
        $r = expmod($g, $k, $p) % $q;
        $s = (invmod($k, $q) * (hex($h->($m)) + $x * $r)) % $q;
    }
    ($r, $s)
}

sub dsa_verify
{
    my ($r, $s, $h, $m, $p, $q, $g, $y) = @_;
    return 0 if ($s == 0) || ($r == 0) || ($r >= $q) || ($s >= $q);
    my $w  = invmod($s, $q);
    my $u1 = (hex($h->($m)) * $w) % $q;
    my $u2 = ($r * $w) % $q;
    my $v0 = expmod($g, $u1, $p);
    my $v1 = expmod($y, $u2, $p);
    my $v  = (($v0 * $v1) % $p) % $q;
    $v == $r
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