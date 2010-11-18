
use strict;
use warnings;



use ExtUtils::MakeMaker 6.31;



my %WriteMakefileArgs = (
  'ABSTRACT' => 'Classes, roles, and types for use by other Antispam modules',
  'AUTHOR' => 'Dave Rolsky <autarch@urth.org>',
  'BUILD_REQUIRES' => {
    'Test::More' => '0.88',
    'Test::Most' => '0'
  },
  'CONFIGURE_REQUIRES' => {
    'ExtUtils::MakeMaker' => '6.31'
  },
  'DISTNAME' => 'Antispam-Toolkit',
  'EXE_FILES' => [],
  'LICENSE' => 'artistic_2',
  'NAME' => 'Antispam::Toolkit',
  'PREREQ_PM' => {
    'Archive::Zip' => '0',
    'BerkeleyDB' => '0',
    'DateTime' => '0',
    'File::Temp' => '0',
    'List::AllUtils' => '0',
    'Moose' => '0',
    'MooseX::Params::Validate' => '0',
    'MooseX::StrictConstructor' => '0',
    'MooseX::Types' => '0',
    'MooseX::Types::Common' => '0',
    'MooseX::Types::Path::Class' => '0',
    'Path::Class' => '0',
    'autodie' => '0',
    'namespace::autoclean' => '0'
  },
  'VERSION' => '0.05',
  'test' => {
    'TESTS' => 't/*.t'
  }
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.56) } ) {
  my $br = delete $WriteMakefileArgs{BUILD_REQUIRES};
  my $pp = $WriteMakefileArgs{PREREQ_PM};
  for my $mod ( keys %$br ) {
    if ( exists $pp->{$mod} ) {
      $pp->{$mod} = $br->{$mod} if $br->{$mod} > $pp->{$mod};
    }
    else {
      $pp->{$mod} = $br->{$mod};
    }
  }
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



