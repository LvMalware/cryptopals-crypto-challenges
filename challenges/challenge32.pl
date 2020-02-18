use strict;
use warnings;
require "./challenge31.pl";
#---------------------------------
#The Challenge:
#Reduce the sleep in your "insecure_compare" until your previous solution breaks
# (Try 5ms to start.)
#Now break it again.

#Me: WHAT??? For real? Meee...

#--------------------------------

sub test
{
    #I found the breaking point of challenge 31 to be at 2ms... at this point
    #the code can't recognize the differences between the delay of the equals
    #function and the delay of the web requests... Maybe the high performance of
    #the Mojolicious framework is a disadvantage on this case (for the attacker)
    
    #I'm not sure how it can be solved... but I think it can be done increasing
    #the number of times each byte is tested.
    #As I use the average delay time of each byte, choosing the byte with the
    #greater delay, may be the case that increasing the number of tests can also
    #improve the precision... (or that is what I hope)

    #let's try with 100 tests per byte ... this may take forever :/
    my $signature = HMAC_BREAK::str_hex(
        HMAC_BREAK::find_hmac("lvmalware", 100, 20)
    );
    #52e4870fa5d4ed0e5d160ed9a11b5de9f5ab42fc
    print "HMAC: $signature\n";

    my ($elapsed, $code) = HMAC_BREAK::request("lvmalware", $signature);
    print "The HMAC is correct!\n" if $code == 200;
    print "I'm a failure\n" if $code != 200;
}

test unless caller;