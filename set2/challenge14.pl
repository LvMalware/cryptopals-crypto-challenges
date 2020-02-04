use utf8;
use strict;
use warnings;
use MIME::Base64;
use Crypt::Mode::ECB;
require "./challenge9.pl";

#the random bytes must be fixed, otherwise we won't be able to decrypt the data
my $random_key;
my $random_bytes;
my $unknown_data = decode_base64(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" .
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" .
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" .
                "YnkK"
                );

sub ecb_oracle
{
    $random_bytes  = join '', map {
        chr rand 256
        } 0 .. rand 100 unless $random_bytes;
    $random_key = join '', map { chr rand 256 } 1 .. 16 unless $random_key;
    my $crypt = Crypt::Mode::ECB->new("AES", 0);
    my $input = $random_bytes . shift . $unknown_data;
    $crypt->encrypt(PKCS7::pkcs7_pad($input, 16), $random_key);
}

sub find_block_size
{
    my $byte = "A";
    my %block_sizes;
    for (my $i = 0; $i < 64; $i++)
    {
        my $cipher = ecb_oracle($byte x $i);
        $block_sizes{length($cipher)} ++;
    }
    my @sizes = sort keys %block_sizes;
    $sizes[1] - $sizes[0];
}

sub split_16bytes { map { substr $_[0], $_ * 16, 16 } 0 .. length($_[0])/16 }

sub find_repetitions
{
    my $data   = shift;
    my @blocks = map { quotemeta ($_) } split_16bytes($data);
    my %repetitions;
    for (@blocks)
    {
        $repetitions{$data =~ s/$_//g} = $_ if $_;
    }
    
    my @sorted_rep = sort keys %repetitions;
    return $repetitions{$sorted_rep[-1]};
}

sub find_random_bytes_length
{
    #This function find the count of random bytes that are being added to our
    #data before the encryption. It can be very usefull later.

    my $block_size  = find_block_size;
    #the size of the data to feed the ecb_oracle()
    my $test_size   = $block_size * 5;
    #feeding the ecb_oracle() with 5 times the block size will ensure that at
    #least three blocks will appear repeated on the cipher data
    my $test_data   = "A" x $test_size;
    my $cipher_data = ecb_oracle($test_data);
    #now we find the block that repeats at least 4 times, and we will have an
    #idea of how our data seems when encrypted with the random key.
    my $block = find_repetitions $cipher_data;
    #The easiest way to get repeated blocks is to use a repetition of one byte
    $test_data = "A" x $block_size;
    $cipher_data = ecb_oracle $test_data;
    #now we feed the ecb_oracle() function with a increasing amount of data
    #until we get only one of these blocks
    while (($cipher_data =~ /$block/g) != 1)
    {
        $test_data .= "A";
        $cipher_data = ecb_oracle $test_data;
    }
    #finally, we find the index where our block appear, multiply the block size
    #and subtract the length of our test data
    $cipher_data =~ /$block/;
    my $block_index = pos $cipher_data;
    $block_index - length($test_data);
}

sub next_byte
{
    my $prefix_len  = shift;
    my $block_size  = shift;
    my $known_text  = shift;
    my $prefix_data = "A" x ($block_size - $prefix_len % $block_size);
    
    my $short_len   = $block_size - ((1 + length($known_text)) % $block_size);

    my $test_range  = $prefix_len + length($prefix_data) +
                      $short_len  + length($known_text)  + 1;
    
    my $short_block = $prefix_data . "A" x $short_len;
    
    my $cipher_data = ecb_oracle($short_block);

    for my $byte (1 .. 255)
    {
        my $tmp = ecb_oracle($short_block . $known_text . chr($byte));
        if (substr($tmp, 0, $test_range) eq
            substr($cipher_data, 0, $test_range))
        {
            return chr($byte);
        }
    }
}

sub ecb_byte_at_time
{
    my $prefix_len = find_random_bytes_length;
    my $block_size = find_block_size;
    my $known_data = "";
    my $data_size  = length(ecb_oracle("")) - $prefix_len;
    for my $i (1 .. $data_size)
    {
        $known_data .= next_byte($prefix_len, $block_size, $known_data);
    }
    PKCS7::pkcs7_unpad $known_data;
}

sub test
{
    #That one took longer... but it was worth it
    my $decrypted = ecb_byte_at_time;
    print "Decrypted: \"$decrypted\"\n";
    if ($unknown_data eq $decrypted)
    {
        print "Decryption works!\n";
    }
}

test unless caller;