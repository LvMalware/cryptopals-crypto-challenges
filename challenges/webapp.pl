use strict;
use warnings;
use Mojolicious::Lite;
use List::MoreUtils 'zip';
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
    my %hash;
    @hash{split //, shift} = split //, shift;
    while (my ($b1, $b2) = each %hash)
    {
        return 0 if ($b1 ne $b2);
        sleep 0.005;
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