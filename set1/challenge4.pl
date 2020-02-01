use utf8;
use strict;
use warnings;
require "./pretty.pl";
require "./challenge3.pl";

my $file;
open ($file, "< :encoding(UTF-8)", "4.txt");

my $index = 0;
my ($cipher_text, $line_number, $decode_char);
my $words_count = 0;
while (my $line = <$file>)
{
    chomp $line;
    printf("Processing line #%d ...\n", $index);
    my ($char, $count) = XorUtils::find_char(PrettyPrinting::hex_decode($line));
    if ($count)
    {
        if ($count > $words_count)
        {
            $cipher_text = $line;
            $line_number = $index;
            $words_count = $count;
            $decode_char = $char;
        }
    }
    $index ++;
}

close $file;
printf("Line #%d: %s\n", $line_number, $cipher_text);
print "Encoded with char $decode_char (" . chr($decode_char) . ")\n";
print "Original text: ";
print XorUtils::unxor(PrettyPrinting::hex_decode($cipher_text), $decode_char);
print "\n";

#Line #170: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
#Encoded with char 53 (5)
#Original text: Now that the party is jumping