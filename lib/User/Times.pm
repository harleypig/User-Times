package User::Times;

#ABSTRACT: Return user login info from utmp files in a hash suitable for determining how long and when people have been logged in.

#use 5.10
use strict;
use warnings;

use Carp;
use User::Utmp qw( :constants );

use Sub::Exporter -setup => { exports => [ 'user_times' ] };

# Default to UTMPX
#
# If ! HAS_UTMPX or UTMP is specifically requested
#   then revert to Utmp functions.

sub user_times {

  my %args = @_ == 1     ? ( 'file', +shift )
           : @_ % 2 == 0 ? @_
           : do { carp 'Invalid parameter list' };

  $args{ utmp } ||= 0;

  my ( $setfile, $getrec );

  if ( HAS_UTMPX() && ! $args{ utmp } ) {

    $setfile        = \&User::Utmp::utmpxname;
    $getrec         = \&User::Utmp::getutx;
    $args{ file } ||= User::Utmp::WTMPX_FILE;

  } else {

    $setfile        = \&User::Utmp::utmpname;
    $getrec         = \&User::Utmp::getut;
    $args{ file } ||= User::Utmp::WTMP_FILE;

  }

  $setfile->( $args{ file } );

  # Single record output:
  #
  # $rec = {
  #   ut_addr => "",
  #   ut_exit => { e_exit => 0, e_termination => 0 },
  #   ut_host => ":0",
  #   ut_id   => "ts/1",
  #   ut_line => "pts/1",
  #   ut_pid  => 6003,
  #   ut_time => 1322780606,
  #   ut_tv   => { tv_sec => 1322780606, tv_usec => 381683 },
  #   ut_type => 7,
  #   ut_user => "james",
  # }

  # Convert to:
  #
  # james => {
  #   loggedin => 1,
  #   sessions  => [
  #     { addr     => '',
  #       crash    => 0,
  #       host     => ':0',
  #       id       => 'ts/1',
  #       line     => 'pts/1',
  #       pid      => 6003,
  #
  #       exit     => 0,
  #       termination => 0,
  #
  #       in       => 0,
  #       in_usec  => 0,
  #       out      => 1322780606,
  #       out_usec => 381683,
  #     },
  #   ],
  #   session => {
  #     6003 => \%session_hash (see above),
  #   },
  # },

  # PID     USER_PROCESS username is login
  # SAMEPID DEAD_PROCESS username is logout

  my %session_tmpl = (

    addr     => '',
    crash    => 0,
    host     => '',
    id       => '',
    line     => '',
    pid      => 0,

    exit        => 0,
    termination => 0,

    in       => 0,
    in_usec  => 0,
    out      => 0,
    out_usec => 0,

  );

  my @simple_fields = qw( addr crash host id line pid );

  my %info;

  for my $rec ( $getrec->() ) {

    #next if $rec->{ ut_user } eq ''; # How does this happen? Do I need to
    #                                 # worry about it?

    # Ignore or special handling for these usernames
    next if $rec->{ ut_user } =~ /^(?:LOGIN|reboot|runlevel|shutdown)$/i;

    next unless $rec->{ ut_user } eq 'james';

    if ( $rec->{ ut_type } eq BOOT_TIME() ) {

      # Make sure any user not logged out is marked as logged out, with 'crash'
      # set to true for any session not already logged out.

    } elsif ( $rec->{ ut_type } eq USER_PROCESS() ) { # create a new session (user has logged in)

      next if $rec->{ ut_user } eq ''; # as far as I can tell, this shouldn't happen, except on boot.

      my $user = $info{ $rec->{ ut_user } } ||= { loggedin => 0, session => [], session => {} };

      my %session = %session_tmpl;

      $session{ $_ } = $rec->{ "ut_$_" }
        for @simple_fields;

      $session{ $_ } = $rec->{ "ut_exit" }{ "e_$_" }
        for qw( exit termination );

      $session{ in }      = $rec->{ ut_tv }{ tv_sec };
      $session{ in_usec } = $rec->{ ut_tv }{ tv_usec };

      push @{ $user->{ sessions } }, \%session;

$DB::single = 1 if exists $user->{ session }{ $session{ pid } };

      croak "Does this happen often enough I need to program around it?"
        if exists $user->{ session }{ $session{ pid } };

      $user->{ session }{ $session{ pid } } = \%session;
      $user->{ loggedin }++;

printf "login %15s: %2d (%s)\n",
  $rec->{ ut_user }, $user->{ loggedin }, scalar localtime( $session{ in } );

      push @{ $user->{ inout } }, [ $session{ in }, 0 ]
        if $user->{ 'loggedin' } == 1;

    } elsif ( $rec->{ ut_type } eq DEAD_PROCESS() ) {

      # Some programs will null the ut_user field, so if ut_user is null then
      # we need to find the pid amongst the data.

      unless ( exists $info{ $rec->{ ut_user } } ) {

        find pid!

      }

      # I may need to revisit this ... in the case of a DEAD_PROCESS for
      # a user that doesn't have an equivalent USER_PROCESS I'm going to
      # assume the login happened *before* the beginning of the current file
      # and ignore it. Also has the side effect of ignoring users explicitly
      # ignored in the USER_PROCESS section above.

      next unless exists $info{ $rec->{ ut_user } };

      my $user = $info{ $rec->{ ut_user } };

      # Ignore if the pid doesn't exist, another way of assuming the user
      # logged in before the beginning of the utmp file.

      next unless exists $user->{ session }{ $rec->{ ut_pid } };

      $user->{ session }{ $rec->{ ut_pid } }{ out }      = $rec->{ ut_tv }{ tv_sec };
      $user->{ session }{ $rec->{ ut_pid } }{ out_usec } = $rec->{ ut_tv }{ tv_usec };

$DB::single = 1 if $user->{ loggedin } == 1;

      $user->{ loggedin }--;

printf "login %15s: %2d (%s)\n",
  $rec->{ ut_user }, $user->{ loggedin }, scalar localtime( $user->{ session }{ $rec->{ ut_pid } }{ out } );

$DB::single = 1 if $user->{ loggedin } == 0;

      $user->{ inout }[-1][-1] = $rec->{ ut_tv }{ tv_sec }
        if $user->{ loggedin } == 0;

    }
  }

  $DB::single = 1;

  return \%info;

}

1;
