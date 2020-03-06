use utf8;
use strict;
use bigint;
use warnings;
use Math::BigInt;
use ntheory qw(invmod);
use Digest::SHA qw(sha1_hex);
use lib ".";
eval 'use DSA';
require "./utils.pl";

sub load_file
{
    open my $file, "< :encoding(UTF-8)", "44.txt"
        || die "$0: can t open file for reading: $!";
    my @data;
    until (eof($file))
    {
        my $sig = {};
        for (my $i = 0; $i < 4; $i ++)
        {
            chomp(my $line = <$file>);
            my ($c, $d) = split ': ', $line;
            $sig->{$c}  = $d;
        }
        push @data, $sig;
    }
    @data;
}

sub recover_x
{
    my ($r, $s, $k, $h, $q) = @_;
    (($s * $k - $h) * invmod($r, $q)) % $q
}

sub find_x_from_repeated_k
{
    my ($data, $p, $q, $g) = @_;
    for (my $i = 0; $i < @$data - 1; $i++)
    {
        for (my $j = $i + 1; $j < @$data; $j++)
        {
            if ($data->[$i]{'r'} == $data->[$j]{'r'})
            {
                print "Same K: $i and $j\n";
                my $s1 = Math::BigInt->new($data->[$i]{'s'});
                my $s2 = Math::BigInt->new($data->[$j]{'s'}); 
                my $ds = ($s1 - $s2) % $q;
                my $m1 = hex($data->[$i]{'m'});
                my $m2 = hex($data->[$j]{'m'});
                my $dm = ($m1 - $m2) % $q;
                my $k  = ($dm * invmod($ds, $q)) % $q;

                my $x1 = recover_x(
                    $data->[$i]{'r'}, $data->[$i]{'s'},
                    $k, hex($data->[$i]{'m'}), $q
                );
                
                my $x2 = recover_x(
                    $data->[$j]{'r'}, $data->[$j]{'s'},
                    $k, hex($data->[$j]{'m'}), $q
                );

                return $x1 if ($x2 == $x1);

                return $x1 if dsa_verify(
                    $data->[$i]{'r'}, $data->[$i]{'s'}, \&sha1_hex,
                    $data->[$i]{'msg'}, $p, $q, $g, Utils::expmod($g, $x1, $p)
                );

                return $x2 if dsa_verify(
                    $data->[$j]{'r'}, $data->[$j]{'s'}, \&sha1_hex,
                    $data->[$j]{'msg'}, $p, $q, $g, Utils::expmod($g, $x2, $p)
                );

            }
        }
    }

    die "$0: can't find the correct K";
}

sub test
{

    my $p = hex(
        '800000000000000089e1855218a0e7dac38136ffafa72eda7' .
        '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6' .
        '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe' .
        'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2' .
        'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87' .
        '1a584471bb1'
    );
 
    my $q = hex('f4f47f05794b256174bba6e9b396a7707e563c5b');
 
    my $g = hex(
        '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119' .
        '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5' .
        '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047' .
        '0f5b64c36b625a097f1651fe775323556fe00b3608c887892' .
        '878480e99041be601a62166ca6894bdd41a7054ec89f756ba' .
        '9fc95302291'
    );

    my $y = hex(
        '2d026f4bf30195ede3a088da85e398ef869611d0f68f07' .
        '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8' .
        '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519' .
        'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430' .
        'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3' .
        '2971c3de5084cce04a2e147821'
    );

    my @data = load_file;
    my $x    = find_x_from_repeated_k(\@data, $p, $q, $g);
    print "X: $x\n";
    if (sha1_hex($x->to_hex) eq 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
    {
        print "The X found is correct!\n"
    }
    else
    {
        die "The X found is wrong!"
    }
}

test unless caller;
