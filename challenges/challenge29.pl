use utf8;
use strict;
use warnings;
require "./sha1.pl";

my $secret_key;

sub md_pad
{
    my $message = shift;
    my $length  = length($message) * 8;
    $message .= "\x80";
    $message .= "\x00" while (((8 * length($message)) % 512)) != 448;
    $message . pack("Q>", $length)
}

sub choose_key
{
    my $words = "/usr/share/dict/words";
    my $count = `wc -l $words | cut -d " " -f1`;
    my $index = int rand $count;
    my $file;
    open $file, "< :encoding(UTF-8)", $words;
    while ($index)
    {
        <$file>;
        $index --;
    }
    $secret_key = <$file>;
    chomp $secret_key;
    close $file;
}

sub validate_digest { SHA1->new()->sha1_mac($secret_key, $_[0]) eq $_[1] }

sub create_digest
{
    choose_key unless $secret_key;
    SHA1->new()->sha1_mac($secret_key, shift)
}

sub sha1_mac_attack
{
    my ($message, $digest) = @_;
    my $admin = ";admin=true";
    for my $len (0 .. 50)
    {
        my @sha_stat = map hex, unpack("(A8)*", $digest);
        my $pad_msg  = md_pad("A" x $len . $message) . $admin;
        my $fake_msg = substr($pad_msg, $len);
        my $fake_mac = SHA1->new()->sha1_sum(
            $admin, 8*length($pad_msg), @sha_stat
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
    my ($fake_msg, $fake_mac) = sha1_mac_attack($msg, $mac);
    print "Fake MAC: $fake_mac\n";
    print "Fake message: $fake_msg\n";
    if (validate_digest $fake_msg, $fake_mac)
    {
        print "The exploitation was a success!\n";
    }
    else
    {
        die "Failed to exploit the SHA-1 MAC";
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