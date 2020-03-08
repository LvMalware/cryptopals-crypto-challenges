package RSA;
use utf8;
use strict;
use bigint;
use warnings;
use Math::BigInt;
use base 'Exporter';
use Math::Prime::Util;
use ntheory qw/invmod/;

our $VERSION = 0.1;
our @EXPORT  = qw(rsa_encrypt rsa_decrypt);

sub new
{
    my $self = shift;
    my %args = @_;
    
    my $data = {
        key_len => $args{key_len} || 64
    };

    unless (defined($args{p}) || defined($args{q}))
    {
        my ($e, $t) = (3, 0);
        my $p = Math::Prime::Util::random_nbit_prime($data->{key_len} / 2);
        my $q = Math::Prime::Util::random_nbit_prime($data->{key_len} / 2);
        my $n = $p * $q;
        while (_MDC($e, $t) != 1)
        {
            $p = Math::Prime::Util::random_nbit_prime($data->{key_len} / 2);
            $q = Math::Prime::Util::random_nbit_prime($data->{key_len} / 2);
            $n = $p * $q;
            $t = ($p - 1) * ($q - 1);
        }
        $data->{e} = 3;
        $data->{p} = $p;
        $data->{q} = $q;
        $data->{n} = $n;
        $data->{t} = $t;
    }
    else
    {
        $data->{p} = $args{p};
        $data->{q} = $args{q};
        $data->{n} = $args{p} * $args{q};
        $data->{t} = ($args{p} - 1) * ($args{q} - 1);
        $data->{e} = 2;
        $data->{e} ++ while (_MDC($data->{e}, $data->{t}) != 1);
    }
    $data->{d} = invmod($data->{e}, $data->{t});
    bless $data, $self;
}

sub encrypt { my $self = shift; rsa_encrypt($_[0], $self->{n}, $self->{e}) }

sub decrypt { my $self = shift; rsa_decrypt($_[0], $self->{n}, $self->{d}) }

#Modular Exponetial function from Rosetta Code
#Avaiable at https://rosettacode.org/wiki/Modular_exponentiation#Perl
#Accessed in 18/feb/2020
sub _expmod
{
    my($a, $b, $n) = @_;
    my $c = 1;
    do {
        ($c *= $a) %= $n if $b % 2;
        ($a *= $a) %= $n;
    } while ($b = int $b/2);
    $c;
}

#convert a string to an integer
sub _str_int { hex join '', map {sprintf "%02x", ord $_} split //, $_[0] }
#convert an integer to a string
sub _int_str
{
    my $hex = $_[0]->to_hex();
    $hex = length($hex) % 2 ? "0$hex" : $hex;
    join '', map {chr hex} $hex =~ /.{2}/g;
}

sub _MDC { $_[1] ? _MDC($_[1], $_[0] % $_[1]) : $_[0] }

sub rsa_encrypt { _expmod(_str_int($_[0]), $_[2], $_[1]) }

sub rsa_decrypt { _int_str(_expmod($_[0], $_[2], $_[1])) }

return 1;