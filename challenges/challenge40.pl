use utf8;
use strict;
use bigint;
use warnings;
use ntheory qw/invmod/;
use lib '.';
eval 'use RSA'; #this avoid vscodium to display a module not found error

sub crt_decrypt
{
    my ($c_0, $c_1, $c_2, $n_0, $n_1, $n_2) = @_;
    my ($m_0, $m_1, $m_2) = ($n_1 * $n_2, $n_0 * $n_2, $n_0 * $n_1);
    my $result = (
        $c_0 * $m_0 * invmod($m_0, $n_0) +
        $c_1 * $m_1 * invmod($m_1, $n_1) +
        $c_2 * $m_2 * invmod($m_2, $n_2)
    ) % ($n_0 * $n_1 * $n_2);
    $result->broot(3)
}

sub test
{
    my $rsa0 = RSA->new(key_len => 1024);
    my $rsa1 = RSA->new(key_len => 1024);
    my $rsa2 = RSA->new(key_len => 1024);
    my $text = "RSA is very secure... but the chinese developed a method that" .
    " can break it years before it was even created!";
    my @c_n  = (
        $rsa0->encrypt($text), $rsa1->encrypt($text), $rsa2->encrypt($text)
    );
    my @n_n  = ( $rsa0->{n}, $rsa1->{n}, $rsa2->{n} );
    my $dec  = crt_decrypt(@c_n, @n_n);
    my $msg  = RSA::_int_str($dec);
    print "Original text: $msg\n";
}

test unless caller;