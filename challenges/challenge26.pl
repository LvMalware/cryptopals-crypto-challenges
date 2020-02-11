use utf8;
use strict;
use warnings;
require "./utils.pl";
require "./challenge18.pl";

my $aes_key = Utils::random_bytes(16);

sub encrypt_info
{
    my $string  = shift =~ s/\;?\=?//rg;
    my $prepend = "comment1=cooking%20MCs;userdata=";
    my $append  = ";comment2=%20like%20a%20pound%20of%20bacon";
    my $data    = $prepend . $string . $append;
    AES_CTR::aes_ctr($data, $aes_key);
}

sub admin_check
{
    my $data   = shift;
    my $string = AES_CTR::aes_ctr($data, $aes_key);
    print "$string\n"; #just for testing
    ($string =~ /\;admin\=true/) ? 1 : 0
}

sub find_prefix_length
{
    my $cipher_1 = encrypt_info "A";
    my $cipher_2 = encrypt_info "B";
    for (my $x = 0; $x < length($cipher_1); $x ++)
    {
        return $x if (substr($cipher_1, $x, 1) ne (substr($cipher_2, $x, 1)))
    }
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

    my $prefix_len = find_prefix_length;
    my $user_data  = "bitflipping_attack?admin?true";
    my $encrypted  = encrypt_info $user_data;
    my $index_sem  = $prefix_len + index($user_data, "?");
    my $index_equ  = $prefix_len + rindex($user_data, "?");
    my $semicolon  = chr(ord(substr($encrypted, $index_sem, 1)) ^ 4);
    my $equalsign  = chr(ord(substr($encrypted, $index_equ, 1)) ^ 2);
    substr($encrypted, $index_sem, 1) = $semicolon;
    substr($encrypted, $index_equ, 1) = $equalsign;
    $encrypted;
}

sub test
{
    my $admin_account = get_admin;
    if (admin_check $admin_account)
    {
        print "It works!\n"
    }
    else
    {
        print "I'm a failure\n"
    }
}

test unless caller;