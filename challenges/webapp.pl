use strict;
use warnings;
use Mojolicious::Lite;
use List::MoreUtils 'zip';
use Time::HiRes qw(usleep); #for a more precise sleep function
require "./sha1.pl";
use lib ".";
use HMAC;

sub sha1_hmac
{
    my $message = shift;
    HMAC::get_hmac(
        hash    =>  sub { SHA1->new()->sha1_sum(shift) },
        key     => "MY SECRET KEY!!!",
        msg     => $message,
        bs      => 64
    )
}

sub insecure_equals
{
    my ($str1, $str2) = @_;
    for (my $i = 0; $i < length($str1); $i ++)
    {
        my $byte1 = ord substr($str1, $i, 1);
        my $byte2 = ord substr($str2, $i, 1);
        return 0 if ($byte1 != $byte2);
        usleep(50000); #1 millisecond = 1000 microseconds
    }
    return 1;
}

sub setup_webapp
{
    get "/test" => sub {
        my $req  = shift;
        my $file = $req->param('file');
        my $sign = $req->param('signature');
        if (insecure_equals(sha1_hmac($file), $sign))
        {
            $req->render(text => "Good signature for: $file", status=>200)
        }
        else
        {
            $req->render(text => "Bad signature for: $file", status=>500)
        }
    }
}

setup_webapp;
app->start