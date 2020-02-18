package DiffieHellman;
use strict;
use Math::BigInt;
use warnings;
use base 'Exporter';

our $VERSION = 0.1;
our @EXPORT  = qw( expmod );

sub expmod {
    my($a, $b, $n) = @_;
    return 0 if ($n == -1);
    my $result = 1;
    $a %= $n;
    while ($b > 0)
    {
        ($result *= $a) %= $n if ($b % 2);
        $b >>= 1;
        ($a *= $a * $a) %= $n;
    }
    $result
}

sub new
{
    srand time;
    my $self = shift;
    my %args = @_;
    unless (defined($args{p}) and defined($args{g}))
    {
        die "You must specify the numbers P and G" 
    }
    my $data = { G => $args{g}, P => $args{p}, SEC_KEY => int rand $args{p} };
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