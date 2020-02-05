use utf8;
use strict;
use warnings;
use MIME::Base64;
require "./challenge9.pl";
require "./challenge10.pl";

my $random_key;

sub encrypt_info
{
    $random_key = join '', map { chr rand 256 } 0 .. 15 unless $random_key;
    my $string  = shift =~ s/\;?\=?//rg;
    my $prepend = "comment1=cooking%20MCs;userdata=";
    my $append  = ";comment2=%20like%20a%20pound%20of%20bacon";
    #comment1=cooking %20MCs;userdata=
    #MY STRING
    #;comment2=%20lik e%20a%20pound%20 of%20bacon
    my $data    = $prepend . $string . $append;
    AES_CBC::encrypt_data(PKCS7::pkcs7_pad($data, 16), $random_key, "\x00"x16);
}

sub admin_check
{
    my $data   = shift;
    my $string = AES_CBC::decrypt_data($data, $random_key, "\x00"x16);
    print "$string\n";
    return 1 if ($string =~ /\;admin\=true/);
    return 0;
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
    #now $fixed_size is equal to the index of where cipher text starts to differ
    my $block_index = int($fixed_size / $block_size) * $block_size;
    #then, we try an increasing amount of data, until we get a block where the
    #cipher texts have an identical block
    for my $count (1 .. $block_size)
    {
        my $cipher_1 = encrypt_info(("A" x $count) . "*");
        my $cipher_2 = encrypt_info(("A" x $count) . "-");
        if (substr($cipher_1, $block_index, $block_size) eq
            substr($cipher_2, $block_index, $block_size))
        {
            #if we find a repeated block after $block_index, the length of the
            #prefix will then be the block index plus the block size minus the
            #count of bytes we added
            return $block_index + ($block_size - $count);
        }
    }
    0;
}

sub get_admin
{
    #   ____________________________
    #  | char | ascii |   binary    |
    #  |______|_______|_____________|
    #  |  =   |  59   | 1 1 1 0 1 1 |
    #  |______|_______|_____________|
    #  |  ;   |  61   | 1 1 1 1 0 1 |
    #  |______|_______|_____________|
    #  |  ?   |  63   | 1 1 1 1 1 1 |
    #  |______|_______|_____________|

    my $block_size  = find_block_size();
    #just in case of a variable prefix length
    my $prefix_len  = find_prefix_length($block_size);
    #find the count of bytes that are needed to complete a block
    my $extra_size  = ($block_size - $prefix_len % $block_size) % $block_size;
    my $extra_bytes = "A" x ($extra_size + $block_size);
    my $payload_str = $extra_bytes . "A"x($block_size - 11) ."?admin?true";
    my $crypt_admin = encrypt_info($payload_str);
    my $semicolon_i = $prefix_len + $extra_size + $block_size - 11;
    my $equalsign_i = $semicolon_i + 6;
    my $tmp_byte_1  = ord(substr($crypt_admin, $semicolon_i, 1));
    my $tmp_byte_2  = ord(substr($crypt_admin, $equalsign_i, 1));
    $tmp_byte_1 ^= 4; #flipping the 5th bit
    $tmp_byte_2 ^= 2; #flipping the 4th bit
    substr($crypt_admin, $semicolon_i, 1) = chr($tmp_byte_1);
    substr($crypt_admin, $equalsign_i, 1) = chr($tmp_byte_2);
    $crypt_admin;
}

sub test
{
    my $admin_account = get_admin();
    if (admin_check($admin_account))
    {
        print "You're admin!\n";
    }
    else
    {
        print "Failed to get admin!\n";
    }
}

test unless caller;