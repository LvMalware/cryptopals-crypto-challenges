use utf8;
use strict;
use warnings;
use MIME::Base64;
use Encode qw (encode);
require "./challenge9.pl";
require "./challenge10.pl";
require "./challenge8.pl";

sub random_key { join '', map{chr rand 256} 1 .. $_[0] }

sub random_cbc_encrypt {
    my $input = shift;
    my $data  = random_key(5+rand(5)) . $input . random_key(5+rand(5));
    my $key   = random_key(16);
    my $iv    = random_key(16);
    AES_CBC::encrypt_data($data, $key, $iv);
}

sub random_ecb_encrypt
{
    my $input = shift;
    my $data  = random_key(5+rand(5)) . $input . random_key(5+rand(5));
    my $key   = random_key(16);
    AES_CBC::ecb_encrypt($data, $key);
}

sub oracle_encrypt
{
    return ("CBC", random_cbc_encrypt(shift)) if (rand(10) < 5);
    return ("ECB", random_ecb_encrypt(shift));
}

sub detect_mode { ECB_DETECT::detect_ecb(shift) > 1 ? "ECB" : "CBC" }

sub test
{
    my $plain = encode("utf-8", "Knock, knock, knockin' on heaven’s door\n"x10);
    for my $x (0 .. 99)
    {
        my ($mode, $encrypted) = oracle_encrypt($plain);
        my $detected = detect_mode($encrypted);
        print "Mode: $mode\n";
        print "Encrypted: " . encode_base64($encrypted) . "\n";
        if ($detected eq $mode)
        {
            print "Detection works!\n\n";
        }
        else
        {
            print "Detection failed!\n\n";
            last;
        }
    }
}

test unless caller;