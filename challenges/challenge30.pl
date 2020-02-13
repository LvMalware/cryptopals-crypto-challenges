use utf8;
use strict;
use warnings;
require "./md4.pl";
require "./utils.pl";

my $secret_key = Utils::choose_key();

sub validate_digest { MD4->new()->get_mac($secret_key, $_[0]) eq $_[1] }

sub create_digest { MD4->new()->get_mac($secret_key, shift) }

sub md4_mac_attack
{
    my ($message, $digest) = @_;
    my $admin = ";admin=true";
    for my $len (0 .. 50)
    {
        my @md4_stat = unpack "V4", pack("H*", $digest);
        my $pad_msg  = MD4::md_pad("A" x $len . $message) . $admin;
        my $fake_msg = substr($pad_msg, $len);
        my $fake_mac = MD4->new()->get_digest(
            $admin, 8*length($pad_msg), @md4_stat
            );
        return ($fake_msg, $fake_mac) if validate_digest($fake_msg, $fake_mac);
    }
    die ("Something went wrong")
}

sub test
{
    my $msg = "comment1=cooking%20MCs;userdata=foo;" .
              "comment2=%20like%20a%20pound%20of%20bacon";
    my $mac = create_digest $msg;
    if (validate_digest $msg, $mac)
    {
        print "MAC authentication - OK\n";
    }
    print "Original MAC: $mac\n";
    my ($fake_msg, $fake_mac) = md4_mac_attack($msg, $mac);
    print "Fake MAC: $fake_mac\n";
    print "Fake message: $fake_msg\n";
    if (validate_digest $fake_msg, $fake_mac)
    {
        print "The exploitation was a success!\n";
    }
    else
    {
        die "Failed to exploit the MD4 MAC";
    }

    if ($fake_msg =~ /\;admin\=true/)
    {
        print "You're admin!\n";
    }
    else
    {
        print "Not admin??\n";
    }
}

test unless caller;