package CTR_BREAK;
use utf8;
use strict;
use warnings;
use MIME::Base64;
require "./challenge3.pl";  #XorUtils::
require "./challenge18.pl"; #AES_CTR::

my $fixed_key;

sub load_file
{
    my $file = shift;
    my $decd = shift || 0;
    my $handler;
    my @file_data;
    open($handler, "< :encoding(UTF-8)", $file)
        || die "$0: failed to open $file: $!";
    while (<$handler>)
    {
        push @file_data, $decd ? decode_base64($_) : $_;
    }
    close $handler;
    \@file_data;
}

sub encrypt_texts
{
    my $texts  = shift;
    $fixed_key = join '', map { chr rand 256 } 1 .. 16 unless $fixed_key;
    my @ciphers;
    for my $plain (@{$texts})
    {
        push @ciphers, AES_CTR::aes_ctr($plain, $fixed_key, 16, 0);
    }
    \@ciphers;
}

sub find_byte
{
    #it looks a lot like challenge 3... let's just use the same code :)
    my ($ch, $freq) = XorUtils::find_char(shift);
    return $ch;
}

sub get_transposed_blocks
{
    my $cipher_texts = shift;
    #a little inefficient? maybe.
    my @sorted_sizes = sort map(length, @{$cipher_texts});
    my $bigger_size  = $sorted_sizes[-1];
    my @transposed_blocks;
    for (my $index = 0; $index < $bigger_size; $index++)
    {
        my $block = "";
        for my $str (@{$cipher_texts})
        {
            $block .= substr($str, $index, 1) if $index < length($str)
        }
        push @transposed_blocks, $block;
    }
    \@transposed_blocks;
}

sub get_keystream
{
    join '', map {chr(find_byte $_) || ''} @{get_transposed_blocks shift};
}

sub attack_ciphers
{
    my $encrypted = shift;
    my $keystream = get_keystream $encrypted;
    my @decrypted;
    push @decrypted, AES_CTR::xor_str($_, $keystream) for @{$encrypted};
    \@decrypted;
}

sub test
{
    #this approach maybe a little inefficient. Probably because of the code
    #used for frequency analysis...
    #TODO: improve the algorithm for finding the single byte xor key
    my $encrypted = encrypt_texts load_file('19.txt', 1);
    my $decrypted = attack_ciphers $encrypted;
    print "$_\n" for @{$decrypted};

}

test unless caller;