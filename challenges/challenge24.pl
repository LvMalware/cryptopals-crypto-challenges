use utf8;
use strict;
use warnings;
require "./challenge21.pl";
require "./utils.pl";

sub encrypt
{
    my ($plain_text, $rng_seed) = @_;
    MT19937::seed_mt($rng_seed);
    join '', map { chr(ord($_) ^ MT19937::rnd(256)) } split //, $plain_text;
}

sub decrypt
{
    encrypt(@_);
}

sub find_seed
{
    my ($cipher_text, $known_text, $seed_size_bits) = @_;
    $seed_size_bits = 16 unless $seed_size_bits;
    my $max_seed = 2 ** $seed_size_bits;
    print "Trying all the possible seeds of $seed_size_bits bits\n";
    print "This may take a while... go get a coffee...\n";
    for (my $seed = 0; $seed < $max_seed; $seed ++)
    {
        if (decrypt($cipher_text, $seed) =~ /$known_text/)
        {
            print "Found seed: $seed\n";
            return $seed;
        }
    }
    die "The seed wasn't of $seed_size_bits bits."
}

sub generate_token
{
    MT19937::seed_mt(time);
    sprintf("%x", MT19937::extract_number());
}

sub verify_token
{
    my ($token, $period) = @_;
    #commonly this password reset tokens have a duration of validity 
    $period = 3600 unless $period;
    my $int_token = hex $token;
    my $timestamp = time;
    for (my $t = ($timestamp - $period); $t < ($timestamp + $period); $t++)
    {
        MT19937::seed_mt($t);
        if (MT19937::extract_number() == $int_token)
        {
            return 1;
        }
    }
    return 0;
}

sub extract_token
{
    my $str = shift;
    $str =~ /;token\=(.*)/;
    $1
}

sub test
{
    #a seed of 16 bits!
    my $seed       = int(rand 2**16);
    #RANDOM PREFIX + KNOWN PLAIN TEXT + TOKEN
    my $data       = Utils::random_bytes(rand 30) . ";user=lvmalware;token=" .
                     generate_token;
    my $encrypted  = encrypt $data, $seed;
    my $found_seed = find_seed $encrypted, "lvmalware";
    
    print "Real seed: $seed\n";
    
    if ($found_seed == $seed)
    {
        my $decrypted = decrypt $encrypted, $found_seed;
        print "Decrypted: $decrypted\n";
        my $token     = extract_token $decrypted;
        print "Token: $token\n";
        if (verify_token $token)
        {
            print "The token is valid!\n"
        }
        else
        {
            print "The token is invalid!\n"
        }
    }
    else
    {
        print "I'm a failure :(\n"
    }
}

test unless caller;