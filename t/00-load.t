#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Dancer::Plugin::Auth::Extensible::Provider::LDAP' ) || print "Bail out!
";
}

diag( "Testing Dancer::Plugin::Auth::Extensible::Provider::LDAP $Dancer::Plugin::Auth::Extensible::Provider::LDAP::VERSION, Perl $], $^X" );
