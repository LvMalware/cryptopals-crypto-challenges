use utf8;
use strict;
use warnings;
require "./utils.pl";
require "./challenge10.pl";

my $random_key = Utils::random_bytes(16);

sub encrypt_info
{
    my $string  = shift =~ s/\;?\=?//rg;
    my $prepend = "comment1=cooking%20MCs;userdata=";
    my $append  = ";comment2=%20like%20a%20pound%20of%20bacon";
    my $data    = $prepend . $string . $append;
    #using the key as IV (very insecure ...)
    AES_CBC::encrypt_data($data, $random_key, $random_key);
}

sub ascii_compliance
{
    for (split //, shift)
    {
        return 1 if ord($_) > 128;
    }
    0
}

sub decrypt_info
{
    my $plain = AES_CBC::decrypt_data(shift, $random_key, $random_key);
    die ("Invalid message: $plain") if (ascii_compliance $plain)
}

sub find_prefix_length
{
    my $block_size = shift;
    my $fixed_size = 0;
    my $byte_a     = encrypt_info("*");
    my $byte_b     = encrypt_info("-");
    while (substr($byte_a, $fixed_size, 1) eq substr($byte_b, $fixed_size, 1))
    {
        $fixed_size ++;
    }
    my $block_index = int($fixed_size / $block_size) * $block_size;
    for my $count (1 .. $block_size)
    {
        my $cipher_1 = encrypt_info(("A" x $count) . "*");
        my $cipher_2 = encrypt_info(("A" x $count) . "-");
        if (substr($cipher_1, $block_index, $block_size) eq
            substr($cipher_2, $block_index, $block_size))
        {
            return $block_index + ($block_size - $count);
        }
    }
    0;
}

sub find_block_size
{
    my $byte = "A";
    my %block_sizes;
    for (my $i = 0; $i < 64; $i++)
    {
        my $cipher = encrypt_info($byte x $i);
        $block_sizes{length($cipher)} ++;
    }
    my @sizes = sort {$a <=> $b} keys %block_sizes;
    $sizes[1] - $sizes[0];
}

sub recover_key
{
    my $block_size = find_block_size;
    my $prefix_len = find_prefix_length $block_size;
    my $plain_text = "X" x $block_size . "Y" x $block_size . "Z" x $block_size;
    my $encrypted  = encrypt_info $plain_text;
    my $fake_data  = substr($encrypted, $prefix_len, $block_size) .
                     "\x00" x $block_size .
                     substr($encrypted, $prefix_len, $block_size);
    eval { decrypt_info $fake_data };
    "$@" =~ /message\: (.*) at/;
    my $plain_error = $1;
    AES_CBC::xor_data(substr($plain_error, 0, $block_size),
                      substr($plain_error, -$block_size, $block_size)
                      );
}

sub test
{
    my $key = recover_key;
    if ($key eq $random_key)
    {
        print "It works!\n";
    }
    else
    {
        print "I'm a failure\n"
    }
}

test unless caller;