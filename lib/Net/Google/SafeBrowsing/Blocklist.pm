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
use Exporter;
our $VERSION = '1.01';
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
# Note: This doesn't fully canonicalize according to 
# http://code.google.com/apis/safebrowsing/reference.html. It doesn't handle the
# IP address conversions, and ".." and "." in paths are handled elsewhere.
sub escaped_uri {
  my ($uristr) = @_;
  my $unesc;
  while (($unesc = URI::Escape::uri_unescape($uristr)) ne $uristr) {
    $uristr = $unesc;
  }
  return URI->new($unesc)->canonical;
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
  print STDERR @_, "\n";
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
  l("Checking URI: '$uristr'");
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

##
# Take a URI string and return the canonicalized de-suffixed/de-prefixed
# substring that matched the blocklist if a match was made. Return undef
# otherwise. See http://code.google.com/apis/safebrowsing/developers_guide.html.
#
sub suffix_prefix_match {
  my Net::Google::SafeBrowsing::Blocklist $self = shift;
  my ($uristr) = @_;
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
  my @host_parts = grep({$_ ne ''} split(/\./, $host));
  my $max_hosts = 5;
  if (@host_parts - 1 < $max_hosts) {
    $max_hosts = @host_parts - 1;
  }
  if (length($host_parts[$#host_parts]) == 2) {
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
      if ($self->check_uri($uristr)) {
        return $uristr;
      }
    }
    for (my $j = 0; $j < $max_paths; ++$j) {
      $p = '';
      for (my $k = 0; $k < @path - $j; ++$k) {
        $p .= $path[$k];
      }
      my $uristr = $h . $p;
      if ($self->check_uri($uristr)) {
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
