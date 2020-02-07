use utf8;
use strict;
use warnings;
use MIME::Base64;
require "./challenge19.pl";

sub test
{
    #hey, its exactly what I did to solve the previous challenge :p
    #even though, it still is not working 100% 
    my $plain_texts = CTR_BREAK::load_file("20.txt", 1);
    bless $plain_texts;
    my $encrypted   = CTR_BREAK::encrypt_texts $plain_texts;
    bless $encrypted;
    my $decrypted   = CTR_BREAK::attack_ciphers $encrypted;
    print "$_\n" for @{$decrypted};
}

test unless caller;