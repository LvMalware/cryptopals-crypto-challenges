#Needed modules: Crypt::ECB, Crypt::OpenSSL::AES
package AES_ECB;
use utf8;
use strict;
use warnings;
use Crypt::Mode::ECB;
use MIME::Base64;
use Exporter qw (import);

our @EXPORT_OK = qw( decrypt_text );

sub encrypt_text { Crypt::Mode::ECB->new('AES', 9)->encrypt($_[0], $_[1]) }
sub decrypt_text { Crypt::Mode::ECB->new('AES', 0)->decrypt($_[0], $_[1]) }

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