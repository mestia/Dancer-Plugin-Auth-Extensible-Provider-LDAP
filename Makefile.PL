use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer::Plugin::Auth::Extensible::Provider::LDAP',
    AUTHOR              => q{David Precious <davidp@preshweb.co.uk>},
    VERSION_FROM        => 'lib/Dancer/Plugin/Auth/Extensible/Provider/LDAP.pm',
    ABSTRACT_FROM       => 'lib/Dancer/Plugin/Auth/Extensible/Provider/LDAP.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    EXE_FILES           => [ ],
    PREREQ_PM => {
        'Test::More' => 0,
        'Mock::Quick' => 0,
        'Dancer::Plugin::Auth::Extensible' => 0,
        'Net::LDAP' => 0,
        
    },
    MIN_PERL_VERSION    => 5.006001,
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer-Plugin-Auth-Extensible-*' },
    META_MERGE => {
        "meta-spec" => { version => 2 },
        resources => {
            repository => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible-Provider-LDAP',
            bugtracker => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible-Provider-LDAP/issues',
            homepage   => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible-Provider-LDAP/',
        },
        prereqs => {
            runtime => {
                recommends => {
                }
            }
        }
    },

);
