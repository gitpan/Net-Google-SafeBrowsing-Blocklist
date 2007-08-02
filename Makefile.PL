use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::Google::SafeBrowsing::Blocklist',
    AUTHOR              => 'Dan Born <dan-cpan@danborn.net>',
    VERSION_FROM        => 'lib/Net/Google/SafeBrowsing/Blocklist.pm',
    ABSTRACT_FROM       => 'lib/Net/Google/SafeBrowsing/Blocklist.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-Google-SafeBrowsing-Blocklist-*' },
);
