#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'Net::Google::SafeBrowsing::Blocklist' );
}

diag( "Testing Net::Google::SafeBrowsing::Blocklist $Net::Google::SafeBrowsing::Blocklist::VERSION, Perl $], $^X" );
