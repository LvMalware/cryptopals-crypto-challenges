package PKCS7;
use utf8;
use strict;
use warnings;
use Exporter qw( import );

our @EXPORT_OK = qw ( pkcs7_pad pkcs7_padded pkcs7_unpad );

sub pkcs7_pad {
    my ($data, $size) = @_;
    return $data if length($data) == $size;
    my $pad_char = $size - length($data) % $size;
    $data . chr($pad_char)x$pad_char;
}

sub pkcs7_padded
{
    my $data  = shift;
    my $last  = ord(substr $data, -1, 1);
    my $block = substr $data, -$last;
    for my $byte (split //, $block)
    {
        return 0 if ord($byte) != $last;
    }
    1;
}

sub pkcs7_unpad
{
    my $data = shift;
    return $data unless pkcs7_padded($data);
    my $last = ord(substr $data, -1, 1);
    substr $data, 0, length($data) - $last;
}

sub test
{
    my $text     = "YELLOW SUBMARINE";
    my $padded   = pkcs7_pad($text, 20);
    my $unpadded = pkcs7_unpad($padded);
    if (pkcs7_padded($padded))
    {
        print "PADDED - OK\n";
    }

    if ($text eq $unpadded)
    {
        print "UNPADDED - OK\n";
    }
}

test unless caller;