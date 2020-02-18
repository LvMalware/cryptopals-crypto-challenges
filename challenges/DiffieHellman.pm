package DiffieHellman;
use strict;
use warnings;
use Math::BigInt;
use Math::BigInt::Random qw( random_bigint );
use base 'Exporter';
our $VERSION = 0.1;
our @EXPORT  = qw( expmod );

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

sub new
{
    my $self = shift;
    my %args = @_;
    unless (defined($args{p}) and defined($args{g}))
    {
        die "You must specify the numbers P and G" 
    }
    my $data = {
        G       => $args{g},
        P       => $args{p},
        SEC_KEY => random_bigint(min=>1, max=>$args{p})
    };
    bless $data, $self;
}

sub get_public_key
{
    my $self = shift;
    unless (defined($self->{PUB_KEY}))
    {
        $self->{PUB_KEY} = expmod($self->{G}, $self->{SEC_KEY}, $self->{P})
    }
    $self->{PUB_KEY}
}

sub get_shared_secret_key
{
    my $self       = shift;
    my $partner_pk = shift;
    unless (defined($self->{SHR_KEY}))
    {
        $self->{SHR_KEY} = expmod($partner_pk, $self->{SEC_KEY}, $self->{P})
    }
    $self->{SHR_KEY}
}