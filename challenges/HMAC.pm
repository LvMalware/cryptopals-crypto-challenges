package HMAC;
use strict;
use warnings;
use base 'Exporter';

our $VERSION = 0.1;
our @EXPORT  = qw(get_hmac);

sub new
{
    #OO interface
    #Params: hash => the hash function; key => the secret key; bs => block size
    my $self = shift;
    my %args = @_;
    my $data = { H => $args{hash}, K => $args{key}, S => $args{bs} };
    bless $data, $self;
}

sub get_digest
{
    my ($self, $message) = @_;
    get_hmac(
        hash => $self->{H},
        key  => $self->{K},
        msg  => $message,
        bs   => $self->{S}
    )
}

sub __xor
{
    my ($str1, $str2) = @_;
    my $xord = '';
    my $size = (length($str1) > length($str2)) ? length($str2) : length($str1);
    for (my $i = 0; $i < $size; $i++)
    {
        $xord .= chr(ord(substr($str1, $i, 1)) ^ ord(substr($str2, $i, 1)))
    }
    $xord
}

sub get_hmac
{
    #functional interface
    #params: hash => the hash function; key => the secret key; msg => message;
    #bs => block size
    my %args = @_;
    my $h = $args{hash};
    my $k = $args{key};
    my $m = $args{msg};
    my $s = $args{bs};
    if (length($k) > $s)
    {
        $k = $h->($k);
    }
    elsif (length($k) < $s)
    {
        $k .= "\x00"x($s - length($k));
    }
    my $opad = __xor("\x5c" x $s, $k);
    my $ipad = __xor("\x36" x $s, $k);
    $h->($opad . $h->($ipad . $m));
}

1;