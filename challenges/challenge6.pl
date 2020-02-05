use utf8;
use POSIX;
use strict;
use warnings;
use MIME::Base64;
use List::Util 'sum';
use List::MoreUtils qw(zip);
require "./pretty.pl";
require "./challenge3.pl";

sub xor_decrypt
{
    my $input   = shift;
    my $key     = shift;
    my ($i, $j) = (0,0);
    my $output  = "";
    while (length($output) < length($input))
    {
        $output .= chr(
            ord(substr($input, $i++)) ^ ord(substr($key, $j++))
                    );
        
        $j = 0 if ($j >= length($key));
    }
    return $output;
}

#One Line ( MUAHAHAHAHA )
sub bin { reverse map{ ($_[0] >> $_) & 1 } 0 .. floor(log($_[0] || 2)/log(2)) }

sub min { $_[0] < $_[1] ? $_[0] : $_[1] }

sub hamming_distance {
    my $distance   = 0;
    my $sequence1  = shift;
    my $sequence2  = shift;
    my $seq_length = min(length($sequence1), length($sequence2));
    for my $i (0 .. $seq_length)
    {
        $distance += sum(
            bin(ord(substr $sequence1, $i, 1) ^ ord(substr $sequence2, $i, 1))
                        );
    }
    return $distance;
}

sub get_key_size
{
    my $input      = shift;
    my $min_length = shift;
    my $max_length = shift;
    my %blocks_size;
    for my $key_size ($min_length .. $max_length)
    {
        my @blocks = map
        {
            substr $input, $_ * $key_size, $key_size
        } 0 .. floor(length($input) / $key_size);
        my @chunks = @blocks[0 .. 3];
        my $distance = 0;
        for (my $i = 0; $i < 4; $i ++)
        {
            for (my $j = $i+1; $j < 4; $j++)
            {
                $distance += hamming_distance($chunks[$i], $chunks[$j]);
            }
        }
        $distance /= 6;
        $blocks_size{$key_size} = $distance / $key_size;
    }
    my @sizes = sort {$blocks_size{$a} <=> $blocks_size{$b}} keys %blocks_size;
    #return key size with least average edit distance (the most likely size)
    return $sizes[0];
}

sub get_slices
{
    return map { substr $_[0], $_ * $_[1], $_[1] } 0 .. length($_[0]) / $_[1];
}

sub transpose_blocks
{
    my $blocks = shift;
    my $size   = shift;
    my @transposed;
    for (my $i = 0; $i < $size; $i ++)
    {
        push @transposed, "";
        for (my $j = 0; $j < scalar @{$blocks}; $j ++)
        {
            if ($i < length($blocks->[$j]))
            {
                $transposed[-1] .= substr($blocks->[$j], $i, 1);
            }
        }
    }
    return @transposed;
}

sub single_byte_key { XorUtils::find_char(shift) }

sub break_xor
{
    my $cipher_text = shift;
    my $min_key_len = shift;
    my $max_key_len = shift;
    my $key_length  = get_key_size($cipher_text, $min_key_len, $max_key_len);
    print "Possible key size: $key_length\n";
    my @size_blocks = get_slices($cipher_text, $key_length);
    my @transposed  = transpose_blocks(\@size_blocks, $key_length);
    print "Blocks transposed into ";
    printf("%d blocks of %d bytes.\n", $key_length,
            length($cipher_text) / $key_length
        );
    my $key = "";
    for my $block (@transposed)
    {
        my ($char, $freq) = single_byte_key($block);
        $key .= chr($char);
    }
    print "The key appears to be: $key\n";
    print "The original text would be:\n\n";
    print xor_decrypt($cipher_text, $key) . "\n";
}

sub test
{
    my $file;
    open($file, "< :encoding(UTF-8)", "6.txt")
        || die "$0: error: $!";
    my $cipher_text;
    while (<$file>)
    {
        $cipher_text .= $_;
    }
    $cipher_text  = decode_base64($cipher_text);
    print "Text size: " . length($cipher_text) . "\n";
    break_xor($cipher_text, 2, 40);
}

test unless caller;