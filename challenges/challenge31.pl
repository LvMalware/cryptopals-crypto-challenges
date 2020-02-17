use utf8;
use strict;
use warnings;
use HTTP::Tiny;
use Time::HiRes;

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

sub find_next_byte
{
    my ($known_bytes, $filename, $times) = @_;
}

sub test
{
    #start the web app by typing: morbo webapp.pl
    #you must have the Mojolicious module installed.

}

test unless caller;
