package FORMAT;
use utf8;
use strict;
use warnings;
use Exporter qw( import );
use JSON qw( encode_json );
require "./challenge9.pl";
require "./challenge10.pl";

our @EXPORT_OK = qw( format_data unformat_data profile_for );

sub format_data
{
    my $data = shift;
    my %structure;
    for my $tuple (split(/\&/, $data))
    {
        my ($key, $value) = split(/\=/, $tuple);
        $structure{$key} = $value;
    }
    \%structure;
}

sub profile_for
{
    my $email = shift =~ s/\&|\=//rg;
    "email=$email&uid=10&role=user";
}

sub encrypt_profile{ AES_CBC::ecb_encrypt(shift, shift) }

sub decrypt_profile
{
    my $crypt = Crypt::Mode::ECB->new('AES', 0);
    my $data  = PKCS7::pkcs7_unpad($crypt->decrypt(shift, shift));
    format_data($data);
}

sub ecb_cut_paste
{
    my $random_key = join '', map {chr rand 256} 1 .. 16;
    
    my $prefix     = 16 - length("email=");
    my $suffix     = 16 - length("admin");
    #add a non-sense email followed by the desired role and a padding
    #email=AAAAAAAAAA admin\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10 &uid=10...
    my $fake_email = "A" x $prefix . "admin" . chr($suffix) x $suffix;
    my $fake_block = encrypt_profile profile_for($fake_email), $random_key;
    #the length of the email have to be N*16 + 13 where N can be 0 or more
    #email=lvmalware. drk@hostname.dom ain&uid=10&role= user
    my $real_email = "lvmalware.drk\@hostname.domain";
    my $mail_block = encrypt_profile profile_for($real_email), $random_key;
    #using the first two blocks with the original email combined with the second
    #block of the fake email, we create a fake profile with role=admin
    my $cut_paste  = substr($mail_block, 0, 48) . substr($fake_block, 16, 16);
    return decrypt_profile($cut_paste, $random_key);
}

sub test
{
    my $admin_profile = ecb_cut_paste();
    print encode_json($admin_profile) . "\n";
    if ($admin_profile->{"role"} eq "admin")
    {
        print "It works!\n";
    }
}

test unless caller;