use utf8;
use strict;
use warnings;
use HTTP::Tiny;
use Time::HiRes;
use List::Util 'sum';

sub request
{
    #makes a GET request to our web application and returns the elapsed time and
    #the response code
    #params: the file and the signature
    my ($file, $signature) = @_;
    my $url      = "http://127.0.0.1:3000/test?file=$file&signature=$signature";
    my $http     = HTTP::Tiny->new();
    my $start    = [ Time::HiRes::gettimeofday() ];
    my $response = $http->get($url);
    my $elapsed  = Time::HiRes::tv_interval($start);
    return ($elapsed, $response->{status});
}

sub str_hex { join '', map { sprintf "%02x", ord $_ } split //, shift }

sub find_next_byte
{
    my ($known_bytes, $filename, $times, $hmac_len) = @_;
    my $length = $hmac_len - (length($known_bytes) + 1);
    my %average;
    
    for my $byte (0 .. 255)
    {
        for my $i (1 .. $times)
        {
            my $signature = str_hex($known_bytes . chr($byte) . "\x00"x$length);
            my ($elapsed, $code) = request $filename, $signature;
            return chr($byte) if ($code == 200);
            $average{$byte} += $elapsed;
        }
        $average{$byte} /= $times;
    }
    my @sorted = sort { $average{$a} <=> $average{$b} } keys %average;
    chr $sorted[-1]
}

sub find_hmac
{
    my ($filename, $times, $hmac_len) = @_;
    my $signature = "";
    print "Trying for find the HMAC for \"$filename\" with $times rounds...\n";
    print "This may take a while...\n";
    for my $c (1 .. $hmac_len)
    {
        $signature .= find_next_byte($signature, $filename, $times, $hmac_len);
    }
    return $signature;
}

sub test
{
    #start the web app by typing: morbo webapp.pl
    #you must have the Mojolicious module installed.

    my $signature = str_hex(find_hmac("lvmalware", 10, 20));
    #52e4870fa5d4ed0e5d160ed9a11b5de9f5ab42fc
    print "HMAC: $signature\n";

    my ($elapsed, $code) = request("lvmalware", $signature);
    print "The HMAC is correct!\n" if $code == 200;
    print "I'm a failure\n" if $code != 200;
}

test unless caller;
