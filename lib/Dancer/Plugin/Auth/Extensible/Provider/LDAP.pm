package Dancer::Plugin::Auth::Extensible::Provider::LDAP;

use strict;
use warnings;

use base "Dancer::Plugin::Auth::Extensible::Provider::Base";
use Net::LDAP;
use Dancer qw(warning);

=head1 NAME

Dancer::Plugin::Auth::Extensible::LDAP - LDAP authentication provider


=head1 DESCRIPTION

This class is a generic LDAP authentication provider.

See L<Dancer::Plugin::Auth::Extensible> for details on how to use the
authentication framework.

This provider requires the following parameters in it's config file:

=over

=item * server

The LDAP server url.

=item * ldapopts

TODO

hash reference of additional Net::LDAP options

=item * basedn

The base dn user for all search queries (e.g. 'dc=ofosos,dc=org').

=item * authdn

This must be the distinguished name of a user capable of binding to
and reading the directory (e.g. 'cn=Administrator,cn=users,dc=ofosos,dc=org').

=item * bindpw

The password of above named user

=item * searchbase

The group where users are to be found (e.g. 'cn=users,dc=ofosos,dc=org' or
'ou=people,dc=donotuse,dc=de')

=item * userrdn

user RDN ( Relative Distinguished Name ) like "uid" or "cn". For example one
can bind to ldap using uid=username,ou=people,dc=donotuse,dc=de or
cn=Administrator,cn=users,dc=ofosos,dc=org

=item * grouprdn

Similar to userrdn, "ou" or "cn" or ...
group RDN prefix for a group DN (e.g. 'ou=webgroup,dc=donotuse,dc=de'
or 'cn=users,dc=donotuse,dc=de')

=item * userattrs

Return user attributes:
 - cn dn name userPrincipalName sAMAcountName uid ...

=item * objectClass

Filter used when searching for users.
For example ('objectClass=posixAccount')

=item * rolefilter

depends on objectClass, for example for posixGroup objectClass rolefilter
is 'memberUid', for groupOfUniqueNames reolefilter is 'uniqueMember=uid'
or 'uniqueMember=cn' and so on.

=item * roles

This is a comma separated list of LDAP group objects that are to be queried.

=back

=cut

=head1 Class methods

=over

=item authenticate_user

Given the userrdn (uid,sAMAccountName,..) and password entered by the user, return true if they are
authenticated, or false if not.

=cut

sub authenticate_user {
    my ($self, $username, $password) = @_;

    my $settings = $self->realm_settings;

    my $ldapopts = $settings->{ldapopts} || "";
    my $ldap = Net::LDAP->new($settings->{server}) or die "$!";

    # do not hardcode userrdn

    my $mesg = $ldap->bind(
        $settings->{userrdn} . "=" . $username . "," . $settings->{searchbase},
        password => $password);

    $ldap->unbind;
    $ldap->disconnect;

    return not $mesg->is_error;
}



=item get_user_details

Given a sAMAccountName return the common name (cn), distinguished name (dn) and
user principal name (userPrincipalName) in a hash ref.

Given uid return user attributes

=cut

sub get_user_details {
    my ($self, $username) = @_;

    my $settings = $self->realm_settings;

    my $ldap = Net::LDAP->new($settings->{server}) or die "$@";

    # try anonymous bind if no authdn is defined
    # if no authdn and password is defined do an anynymous bind?
    # to be tested
    my $mesg;
    if ( $settings->{authdn} ) {
    $mesg = $ldap->bind(
        $settings->{authdn},
        password => $settings->{bindpw});
    }
    else {
        $mesg = $ldap->bind();
    }

    if ($mesg->is_error) {
        warning($mesg->error);
    }

    $mesg = $ldap->search(
        base => $settings->{basedn},
        filter => "(&(objectClass=" . $settings->{objectClass} . ")(". $settings->{userrdn} ."=" . $username . "))",
    );

    if ($mesg->is_error) {
        warning($mesg->error);
    }

    my @extract =  (split(/\s/,$settings->{userattrs}));
    my %props = ();

    if ($mesg->entries > 0) {
        foreach my $ex (@extract) {
            $props{$ex} = $mesg->entry(0)->get_value($ex);
        }
    } else {
        warning("Error finding user details.");
    }

    $ldap->unbind;
    $ldap->disconnect;

    return \%props;
}


=item get_user_roles

Given a CN, return a list of roles that user has.

=cut

sub get_user_roles {
    my ($self, $username) = @_;
    my $settings = $self->realm_settings;

    my $ldap = Net::LDAP->new($settings->{server}) or die "$@";

    # try anonymous bind if no authdn is defined

    my $mesg;
    if ( $settings->{authdn} ) {
        $mesg = $ldap->bind(
            $settings->{authdn},
            password => $settings->{bindpw});
    }
    else {
        $mesg = $ldap->bind();
    }

    if ($mesg->is_error) {
        warning($mesg->error);
    }

    my @relevantroles = split /,/, $settings->{roles};
    my @roles = ();

    foreach my $role (@relevantroles) {
        $mesg = $ldap->search(
            base => $settings->{basedn},
            filter => "(&(|(" . $settings->{rolefilter} . "=" . $username . ")(" . $settings->{rolefilter} . "=" . $username . "," . $settings->{searchbase} . "))(" . $settings->{grouprdn} . "=" . $role . "))",
        );
        if ($mesg->is_error) {
            warning($mesg->error);
        }
        if ($mesg->entries > 0) {
            push @roles, $role;
        }
    }

    $ldap->unbind;
    $ldap->disconnect;

    if (@roles == 0) {
        warning($settings->{roles});
    }

    return \@roles;
}


=back

=cut


1;

