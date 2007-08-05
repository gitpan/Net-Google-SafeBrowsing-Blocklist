use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::Google::SafeBrowsing::Blocklist',
    AUTHOR              => 'Dan Born <danborn@cpan.org>',
    VERSION_FROM        => 'lib/Net/Google/SafeBrowsing/Blocklist.pm',
    ABSTRACT_FROM       => 'lib/Net/Google/SafeBrowsing/Blocklist.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Test::Pod' => 0,
        'fields' => 0,
        'DB_File' => 0,
        'Digest::MD5' => 0,
        'URI' => 0,
        'URI::Escape' => 0,
        'File::stat' => 0,
        'Math::BigInt' => '1.87',
        'Time::HiRes' => 0,
        'Exporter' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-Google-SafeBrowsing-Blocklist-*' },
);
