#Needed modules: Crypt::ECB, Crypt::OpenSSL::AES
package AES_ECB;
use utf8;
use strict;
use warnings;
use Crypt::ECB;
use MIME::Base64;
use Exporter qw (import);

our @EXPORT_OK = qw( decrypt_text );

sub decrypt_text
{
    Crypt::ECB->new(
        -key => $_[1],
        -cipher => "Crypt::OpenSSL::AES",
        -padding => "none"
        )->decrypt($_[0]);
}

sub test
{
    my $key = "YELLOW SUBMARINE";
    my $file;
    open($file, "< :encoding(UTF-8)", "7.txt");
    my $data;
    while (<$file>)
    {
        $data .= decode_base64($_);
    }
    my $plain_text = decrypt_text($data, $key);
    print $plain_text . "\n";
}
test unless caller;