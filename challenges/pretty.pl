#Pretty Printing utils
package PrettyPrinting;

use utf8;
use strict;
use warnings;
use MIME::Base64;
use Exporter qw ( import );
our @EXPORT_OK = qw( hex_encode hex_decode hex_base64 );

sub hex_decode
{
    return join '', map {chr(hex($_))} shift =~/.{2}/g;
}

sub hex_encode
{
    return join '', map {
        (ord($_) < 16) ? sprintf("0%x", ord($_)) : sprintf("%x", ord($_))
        } split //, shift;
}

sub hex_base64
{
    return encode_base64(hex_decode(shift));
}