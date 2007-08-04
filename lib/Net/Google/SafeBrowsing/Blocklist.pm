#   Copyright 2007 Daniel Born
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

=head1 NAME

Net::Google::SafeBrowsing::Blocklist - Query a Google SafeBrowsing table

=head1 SYNOPSIS

  my $blocklist = Net::Google::SafeBrowsing::Blocklist->new(
       $tablename, $dbfile, $apikey);
  my $matched_uri = $blocklist->suffix_prefix_match($uri);
  if (defined($matched_uri)) {
    print "Matched '$matched_uri'\n";
  } else {
    print "No match for '$uri'\n";
  }
  $blocklist->close;

=head1 DESCRIPTION

The Blocklist module performs lookups in the Google SafeBrowsing URI tables. The
$tablename, $dbfile, and $apikey arguments to the constructor should correspond
to the arguments given to the blocklist_updater script.

=head1 METHODS

=over

=cut

package Net::Google::SafeBrowsing::Blocklist;
use strict;
use warnings;
use fields (
    'blocklist',      # Name of Google blocklist
    'dbfile',         # Path to DB_File with URL hashes
    'dbfile_mtime',   # Modification time of dbfile
    'apikey',         # Google API key
    'db',             # Database handle, tied to dbfile
);
use DB_File;
use Digest::MD5;
use URI;
use URI::Escape;
use File::stat;
use Math::BigInt 1.87;
use Time::HiRes;
use Exporter;
our $VERSION = '1.03';
our @ISA = qw(Exporter);

our $MAJORVERSION  = '__MAJOR__';
our $MINORVERSION  = '__MINOR__';
our $TIMESTAMP     = '__TIME__';
our $LASTATTEMPT   = '__LAST__';
our $CLIENTKEY     = '__CKEY__';
our $WRAPPEDKEY    = '__WKEY__';
our $ERRORS        = '__ERRS__';
our @SPECIAL_KEYS = ($MAJORVERSION, $MINORVERSION, $TIMESTAMP, $LASTATTEMPT,
                     $CLIENTKEY, $WRAPPEDKEY, $ERRORS);
our @EXPORT_OK = qw($MAJORVERSION $MINORVERSION $TIMESTAMP $LASTATTEMPT
                    $CLIENTKEY $WRAPPEDKEY $ERRORS @SPECIAL_KEYS);
our %EXPORT_TAGS = (all => \@EXPORT_OK);


# Take a string and return a URI object.
sub escaped_uri {
  my ($uristr) = @_;
  my $unesc;
  while (($unesc = URI::Escape::uri_unescape($uristr)) ne $uristr) {
    $uristr = $unesc;
  }
  return URI->new($unesc)->canonical;
}

sub canonicalized_ip {
  my ($host) = @_;
  use integer;
  my @parts = split(/\.+/, $host);
  if (@parts > 4) {
    return undef;
  }
  my @ip;
  for (my $i = 0; $i < @parts; ++$i) {
    # length checks above are just sanity checks on the string length. Check the
    # actual value with Math::BigInt.
    my $n;
    if ($parts[$i] =~ /^0x([a-fA-F0-9]+)$/) {
      my $val = substr($1, -9);
      $n = Math::BigInt->new('0x' . $val);
    } elsif ($parts[$i] =~ /^0([0-7]+)$/) {
      my $val = substr($1, -12);
      $n = Math::BigInt->from_oct('0' . $val);
    } elsif ($parts[$i] =~ /^(\d+)$/) {
      my $val = substr($1, -11);
      $n = Math::BigInt->new($val);
    } else {
      return undef;
    }
    if ($n->bcmp(255) > 0) {
      if ($i < $#parts) {
        $n->band(0xff);
        push(@ip, $n->bstr);
      } else {
        my $started = 0;
        my $max = 0xffffffff;
        if ($n->bcmp($max) > 0) {
          $n->band($max);
          $started = 1;
        }
        $n = int($n->bstr);
        my $shift;
        for ($shift = 24; $shift >= 0 and @ip < 4; $shift -= 8) {
          my $byte = ($n >> $shift) & 0xff;
          if ($byte == 0 and not $started) {
            next;
          } else {
            $started = 1;
          }
          push(@ip, sprintf('%u', $byte));
        }
        if ($shift >= 0) {
          return undef;
        }
      }
    } else {
      push(@ip, sprintf('%u', $n->bstr));
    }
  }
  while (@ip < 4) {
    push(@ip, '0');
  }
  return join('.', @ip);
}

sub new {
  my ($class, $blocklist, $dbfile, $apikey) = @_;
  my Net::Google::SafeBrowsing::Blocklist $self = fields::new(
      ref $class || $class);
  $self->{blocklist} = $blocklist;
  $self->{dbfile} = $dbfile;
  $self->{apikey} = $apikey;
  $self->maybe_reopen_db;
  return $self;
}

sub maybe_reopen_db {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  my $st;
  if (not ($st = File::stat::stat($self->{dbfile}))) {
    warn "Could not stat db file ", $self->{dbfile};
    return 0;
  }
  if (not defined($self->{dbfile_mtime}) or
      $self->{dbfile_mtime} < $st->mtime) {
    if ($self->{db}) {
      untie(%{$self->{db}});
      $self->{db} = undef;
    }
    my %db;
    if (not tie(%db, 'DB_File', $self->{dbfile}, O_RDONLY, 0, $DB_HASH)) {
      warn "Cannot open db file ", $self->{dbfile}, ": $!";
      return 0;
    }
    $self->{db} = \%db;
    $self->{dbfile_mtime} = $st->mtime;
  }
  return 1;
}

sub l {
#print STDERR @_, "\n";
}

sub blocklist {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  return $self->{blocklist};
}

sub timestamp {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  return $self->{db}->{$TIMESTAMP};
}

sub clientkey {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  return $self->{db}->{$CLIENTKEY};
}

sub wrappedkey {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  return $self->{db}->{$WRAPPEDKEY};
}

##
# Return true if the given canonicalized URI string hashes to an entry found in
# the blocklist.
#
sub check_uri {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  my ($uristr) = @_;
  my $dig = Digest::MD5::md5($uristr);
  return exists($self->{db}->{$dig});
}

=item $blocklist->suffix_prefix_match($uri)

Try to find a match for $uri in this blocklist, according to the suffix/prefix
matching algorithm described in the Google API doc. Return the matching string,
or return undef if there was no match.

=over

=item $uri

a string representing the URI to check

=back

=cut

sub suffix_prefix_match {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  my ($uristr) = @_;
  my @checked_uris;
  my $start = Time::HiRes::time();
  my $matched = $self->suffix_prefix_match_internal($uristr, \@checked_uris);
  my $stop = Time::HiRes::time();
  l("URIs checked:\n", join("\n", @checked_uris), "\n",
    sprintf("Checked %d URIs in %.6f seconds.",
            scalar(@checked_uris), $stop - $start));
  return $matched;
}

sub suffix_prefix_match_internal {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  my ($uristr, $checked_uris) = @_;

  my $store_check_uri = sub {
    push(@{$checked_uris}, $_[0]);
    return $self->check_uri($_[0]);
  };
  
  if (not $self->maybe_reopen_db) {
    return undef;
  }
  if (time() - $self->timestamp >= 1800) {
    warn "Matched failed because timestamp too old: ", $self->timestamp;
    return undef;
  }
  my $uri = escaped_uri($uristr);
  if (not (defined($uri->scheme) and
           ($uri->scheme eq 'http' or $uri->scheme eq 'https'))) {
    return undef;
  }
  my $host = URI::Escape::uri_escape($uri->host);
  my $ip = canonicalized_ip($host);
  my @host_parts;
  if (defined($ip)) {
    push(@host_parts, $ip);
  } else {
    @host_parts = split(/\.+/, $host);
  }
  my $max_hosts = 5;
  if (defined($ip)) {
    $max_hosts = 1;
  } elsif (@host_parts - 1 < $max_hosts) {
    $max_hosts = @host_parts - 1;
  }
  if (not defined($ip) and length($host_parts[$#host_parts]) == 2) {
    --$max_hosts;
  }
  my @segments = $uri->path_segments;
  my @path;
  for (my $i = 0; $i < @segments; ++$i) {
    $segments[$i] = URI::Escape::uri_escape($segments[$i]);
    if ($segments[$i] eq '..') {
      if (@path > 1) {
        pop(@path);
      }
    } elsif ($segments[$i] eq '.') {
      next;
    } elsif ($i > 0 and $segments[$i] eq '') {
      next;
    } else {
      if ($i == 0 or $i < $#segments) {
        $segments[$i] .= '/';
      }
      push(@path, $segments[$i]);
    }
  }
  my $qry;
  if ($uri->query) {
    $qry = $uri->query;
  }
  my $max_paths = 5;
  if (@path < $max_paths) {
    $max_paths = @path;
  }
  for (my $i = 0; $i < $max_hosts; ++$i, shift(@host_parts)) {
    my $h = join('.', @host_parts);
    my $p = join('', @path);
    if (defined($qry)) {
      my $uristr = $h . $p . '?' . $qry;
      if ($store_check_uri->($uristr)) {
        my $method_stop_time = Timer::HiRes::time();
        return $uristr;
      }
    }
    for (my $j = 0; $j < $max_paths; ++$j) {
      $p = '';
      for (my $k = 0; $k < @path - $j; ++$k) {
        $p .= $path[$k];
      }
      my $uristr = $h . $p;
      if ($store_check_uri->($uristr)) {
        return $uristr;
      }
    }
  }
  return undef;
}

sub close {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  if ($self->{db}) {
    untie(%{$self->{db}});
    $self->{db} = undef;
    $self->{dbfile_mtime} = undef;
  }
}

=back

=cut


1;
