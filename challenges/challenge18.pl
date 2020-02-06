package AES_CTR;
use utf8;
use strict;
use warnings;
use MIME::Base64;
use Crypt::Mode::ECB;

sub min { $_[0] < $_[1] ? $_[0] : $_[1] }

sub xor_str
{
    my ($str1, $str2) = @_;
    my $string_size   = min length($str1), length($str2);
    my $output_string = "";
    for (my $i = 0; $i < $string_size; $i ++)
    {
        $output_string .= chr(
            ord(substr($str1, $i, 1)) ^ ord(substr($str2, $i, 1))
            );
    }
    $output_string;
}

sub aes_ctr
{
    my $data    = shift;
    my $key     = shift;
    my $size    = shift || 16;
    my $nonce   = shift || 0;
    #"<" means little endian and ">" means big endian
    my $endian  = shift || "<";
    my $counter = 0;
    my $output  = "";
    for (my $i  = 0; $i < length($data); $i += $size)
    {
        my $crypt     = Crypt::Mode::ECB->new('AES', 0);
        my $keystream = pack "Q${endian}Q${endian}", $nonce, $counter ++;
        my $block     = substr $data, $i, $size;
        $output      .= xor_str $block, $crypt->encrypt($keystream, $key);
    }
    $output;
}

sub test
{
    my $encrypted = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu" .
                    "/6/kXX0KSvoOLSFQ==";
    my $decrypted = aes_ctr decode_base64($encrypted), "YELLOW SUBMARINE";
    print "Decrypted text: $decrypted\n\n";
    my $plain     = "I'll see you on the dark side of the moon";
    my $cipher    = encode_base64 aes_ctr($plain, "YELLOW SUBMARINE");
    print "My plain  text: $plain\n";
    print "My cipher text: $cipher\n";

}

test unless caller;