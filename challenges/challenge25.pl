package RARW_CTR;
use utf8;
use strict;
use warnings;
use MIME::Base64;
use Crypt::Mode::ECB;
require "./utils.pl";
require "./challenge7.pl";
require "./challenge18.pl";

my $aes_key = Utils::random_bytes(16);

sub encrypt_ctr
{
    my ($text, $key) = @_;
    AES_CTR::aes_ctr($text, $key);
}

sub edit_stream
{
    my ($cipher_text, $key, $offset, $new_text) = @_;
    #somewhat inefficient ...
    my $plain_text = encrypt_ctr $cipher_text, $key;
    substr($plain_text, $offset, length($new_text)) = $new_text;
    encrypt_ctr $plain_text, $key;
}

sub leaked_api
{
    my ($cipher_text, $offset, $new_text) = @_;
    edit_stream $cipher_text, $aes_key, $offset, $new_text;
}

sub recover_encrypt
{
    my $file;
    my $data = "";
    open $file, "< :encoding(UTF-8)", "25.txt";
    $data .= decode_base64 $_ while <$file>;
    close $file;
    encrypt_ctr(AES_ECB::decrypt_text($data, "YELLOW SUBMARINE"), $aes_key)
}

sub exploit_edit
{
    my $cipher_text = shift;
    leaked_api $cipher_text, 0, $cipher_text;
}

sub test
{
    my $encrypted = recover_encrypt;
    my $decrypted = exploit_edit $encrypted;
    print "$decrypted\n";
}

test unless caller;
