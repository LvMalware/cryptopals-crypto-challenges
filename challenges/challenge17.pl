use utf8;
use strict;
use warnings;
use MIME::Base64;
require "./challenge9.pl";
require "./challenge10.pl";

my @input_strings = ( "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" );

my $aes_key;
my $aes_iv;

sub encrypt_random
{
    my $string = decode_base64 $input_strings[rand @input_strings];
    $aes_key   = join '', map {chr rand 256} 1 .. 16 unless $aes_key;
    $aes_iv    = join '', map {chr rand 256} 1 .. 16 unless $aes_iv;
    (AES_CBC::encrypt_data($string, $aes_key, $aes_iv), $aes_iv);
}

sub decrypt_check
{
    my ($encrypted, $iv) = @_;
    my $decrypted = AES_CBC::decrypt_data($encrypted, $aes_key, $iv, 0);
    PKCS7::pkcs7_padded($decrypted);
}


sub padding_oracle_block
{
    #This works sometimes and sometimes we get a fucking weird result
    #Tell me if you see what is wrong :)
    my ($block, $iv) = @_;
    my $decrypted    = "";
    for (my $i = length($block) - 1; $i > -1; $i --)
    {
        my $tmp_iv       = substr $iv, 0, $i;
        my $padding_size = length($decrypted) + 1;
        my $spoof_bytes  = join '', map {
            chr(ord($_) ^ $padding_size)
            } split //, $decrypted;

        for my $byte (0 .. 255)
        {
            if (decrypt_check($block, $tmp_iv . chr($byte) . $spoof_bytes))
            {
                substr($decrypted, 0, 0) = chr($byte ^ $padding_size);
                last;
            }
        }
    }
    
    for (my $i = 0; $i < length($iv); $i++)
    {
        my $dec_byte = ord substr($decrypted, $i, 1);
        my $iv_byte  = ord substr($iv, $i, 1);
        substr($decrypted, $i, 1) = chr ($dec_byte ^ $iv_byte);
    };
    $decrypted;
}

sub split_blocks
{
    map { substr $_[0], $_ * $_[1], $_[1] } 0 .. length($_[0])/$_[1] - 1
}

sub padding_oracle_attack
{
    my ($encrypted, $iv) = @_;
    my $block_size       = 16; #we already know the block size
    my $decrypted        = "";
    my @blocks           = ( $iv );
    push @blocks, split_blocks($encrypted, $block_size);
    for (my $i = 1; $i < scalar @blocks; $i++)
    {
        $decrypted .= padding_oracle_block($blocks[$i], $blocks[$i-1]);
    }
    PKCS7::pkcs7_unpad $decrypted;
}

sub test
{
    #still it makes the text a little weird sometimes ... 
    my $decrypted  = padding_oracle_attack(encrypt_random);
    print "$decrypted\n";
}

test unless caller;