package Antispam::Toolkit::Role::EmailChecker;
BEGIN {
  $Antispam::Toolkit::Role::EmailChecker::VERSION = '0.06';
}

use strict;
use warnings;
use namespace::autoclean;

use Antispam::Toolkit::Types qw( NonEmptyStr );
use Carp qw( croak );
use List::AllUtils qw( any );

use Moose::Role;
use MooseX::Params::Validate qw( validated_hash );

requires 'check_email';

around check_email => sub {
    my $orig = shift;
    my $self = shift;
    my %p    = validated_hash(
        \@_,
        email => { isa => NonEmptyStr, optional => 1 },
    );

    return $self->$orig(%p);
};

1;

# ABSTRACT: A role for classes which check whether an email is associated with spam



=pod

=head1 NAME

Antispam::Toolkit::Role::EmailChecker - A role for classes which check whether an email is associated with spam

=head1 VERSION

version 0.06

=head1 SYNOPSIS

  package MyEmailChecker;

  use Moose;

  with 'Antispam::Toolkit::Role::EmailChecker';

  sub check_email { ... }

=head1 DESCRIPTION

This role specifies an interface for classes which check whether a specific
email address is associated with spam.

=head1 REQUIRED METHODS

Classes which consume this method must provide one method:

=head2 $checker->check_email( email => ... )

This method implements the actual spam checking for an email address. The
email will be passed as a named parameter.

=head1 METHODS

This role provides an around modifier for the C<< $checker->check_email() >>
method. The modifier does validation on all the parameters, so there's no need
to implement this in the class itself.

=head1 BUGS

See L<Antispam::Toolkit> for bug reporting details.

=head1 AUTHOR

Dave Rolsky <autarch@urth.org>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2010 by Dave Rolsky.

This is free software, licensed under:

  The Artistic License 2.0

=cut


__END__

