package DecryptUnknown;
use utf8;
use POSIX;
use strict;
use warnings;
use MIME::Base64;
require "./challenge9.pl";
require "./challenge10.pl";
require "./challenge8.pl";

my $random_key;

sub oracle_encrypt2
{
    my $input   = shift;
    $random_key = join '', map{ chr rand 256 } 1 .. 16 unless $random_key;
    my $unknown = #unknown string to be added before the data
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" .
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" .
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" .
                "YnkK";
    my $data    = $input . decode_base64($unknown);
    AES_CBC::ecb_encrypt($data, $random_key);
}

sub find_block_size
{
    my $byte = "A";
    my %block_sizes;
    for (my $i = 0; $i < 64; $i++)
    {
        my $cipher = oracle_encrypt2($byte x $i);
        $block_sizes{length($cipher)} ++;
    }
    my @sizes = sort keys %block_sizes;
    $sizes[1] - $sizes[0];
}

sub detect_mode {
    ECB_DETECT::detect_ecb(oracle_encrypt2("A"x64)) > 1 ? "ECB" : "CBC"
}

sub decrypt_16bytes
{
    #Decrypt an entire block of 16 bytes of the unknown data added to our text
    my $known_text = shift;
    my $block_size = find_block_size();
    my $step       = length($known_text) + 16;
    for (my $i = 1; $i <= $block_size; $i++)
    {
        my $shorter_block = "A" x ($block_size - $i);
        my $cipher_block  = oracle_encrypt2($shorter_block);
        for my $byte (1 .. 255)
        {
            my $tmp = oracle_encrypt2($shorter_block . $known_text. chr($byte));
            if (substr($tmp, 0, $step) eq substr($cipher_block, 0, $step))
            {
                $known_text .= chr($byte);
                last;
            }
        }
    }
    $known_text;
}

sub decrypt_unknown
{
    my $decrypted = "";
    my $data_size = length(oracle_encrypt2(""));
    for my $i (0 .. ceil($data_size / find_block_size))
    {
        #decrypt 16 bytes each time
        #I know that it should be a one byte at a time, but technically it is
        #exactly what I'm doing under the hood.
        $decrypted = decrypt_16bytes($decrypted);
    }
    #unpad the data just to be sure
    PKCS7::pkcs7_unpad($decrypted)
}

sub test
{
    #this one was very cool

    print "Block size: " . find_block_size() . " bytes\n";
    print "Cipher mode: " . detect_mode . "\n";
    my $decrypted = decrypt_unknown();
    my $unknown   = decode_base64(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" .
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" .
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" .
                "YnkK"
                );
    
    print "Decrypted: \"$decrypted\"\n";
    
    if ($decrypted eq $unknown)
    {
        print "Decryption works!\n";
    }
}

test unless caller;
