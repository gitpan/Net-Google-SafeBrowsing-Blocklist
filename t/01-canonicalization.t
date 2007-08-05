#!perl -T

use strict;
use warnings;

BEGIN {
  our %ips = ('1.2.3.4' => '1.2.3.4',
              '012.034.01.055' => '10.28.1.45',
              '0x12.0x43.0x44.0x01' => '18.67.68.1',
              '167838211' => '10.1.2.3',
              '12.0x12.01234' => '12.18.2.156',
              '276.2.3' => '20.2.3.0',
              '0x10000000b' => '0.0.0.11');
  our %uris = ('http://google.com/' => 'http://google.com/',
               'http://GOOgle.com' => 'http://google.com/',
               'http://..google..com../' => 'http://google.com/',
               'http://google.com/%25%34%31%25%31%46' => 'http://google.com/A%1F',
               'http://google^.com/' => 'http://google%5E.com/',
               'http://google.com/1/../2/././' => 'http://google.com/2/',
               'http://google.com/1//2?3//4' => 'http://google.com/1/2?3//4');
};
our (%ips, %uris);

use Test::More tests => scalar(keys(%ips) + 2 * keys(%uris));
use Net::Google::SafeBrowsing::Blocklist;

diag("Testing IP address canonicalization...");
while (my($in, $exp) = each(%ips)) {
  diag("Canonicalize IP '$in' => '$exp'");
  is(Net::Google::SafeBrowsing::Blocklist::canonicalized_ip($in), $exp);
}
while (my($in, $exp) = each(%uris)) {
  diag("URI escape '$in' => '$exp'");
  my ($ip, @host_parts, @path, $qry);
  ok(Net::Google::SafeBrowsing::Blocklist::canonicalized_http_uri(
    $in, \$ip, \@host_parts, \@path, \$qry));
  my $res = 'http://' . join('.', @host_parts) . join('', @path);
  if (defined($qry)) {
    $res .= '?' . $qry;
  }
  is($res, $exp);
}
