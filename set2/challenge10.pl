package AES_CBC;
use utf8;
use strict;
use warnings;
use MIME::Base64;
require "./challenge9.pl";
require "../set1/challenge7.pl";

sub xor_data {
    my ($str1, $str2) = @_;
    my $size = length($str1) < length($str2) ? length($str1) : length($str2);
    my $data;
    for (my $i = 0; $i < $size; $i ++)
    {
        $data .= chr(ord(substr $str1, $i, 1) ^ ord(substr $str2, $i, 1));
    }
    $data;
}

sub encrypt_data
{
    my ($data, $key, $iv) = @_;
    my $size = length($iv);
    my $cipher_data;
    for (my $i = 0; $i < length($data); $i += $size)
    {
        #Though the Crypt::ECB module implements a native padding, we need to
        #disable it in order to allow our pkcs7 padding to work properly
        my $block  = PKCS7::pkcs7_pad(substr($data, $i, $size), $size);
        my $cipher = xor_data($block, $iv);
        $iv        = AES_ECB::encrypt_text($cipher, $key);
        $cipher_data .= $iv;
    }
    $cipher_data;
}

sub decrypt_data
{
    my ($data, $key, $iv) = @_;
    my $size = length($iv);
    my $plain_data;
    for (my $i = 0; $i < length($data); $i += $size)
    {
        my $block = substr $data, $i, $size;
        my $plain = AES_ECB::decrypt_text($block, $key);
        $plain_data .= xor_data($plain, $iv);
        $iv       = $block;
    }
    PKCS7::pkcs7_unpad($plain_data);
}

sub test
{
    my $file;
    open $file, "< :encoding(UTF-8)", "10.txt";
    my $data;
    while (<$file>)
    {
        $data .= decode_base64($_);
    }
    my $iv  = "\00"x16;
    my $key = "YELLOW SUBMARINE";
    print decrypt_data($data, $key, $iv) . "\n";

    my $test_data = "Strawberry Fields Forever";
    print "Encrypting: $test_data\n";
    my $encrypted = encrypt_data($test_data, $key, $iv);
    print "Encrypted: ". encode_base64($encrypted) . "\n";
    my $decrypted = decrypt_data($encrypted, $key, $iv);
    print "Decrypted: $decrypted\n";
    if ($test_data eq $decrypted)
    {
        print "Encryption and decryption working!\n";
    }
}

test unless caller;