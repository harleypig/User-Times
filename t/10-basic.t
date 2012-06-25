
use Test::More tests => 2;

use Data::Dump 'dump';

BEGIN { use_ok( 'User::Times', 'user_times' ) }

ok( exists $main::{ user_times }, 'user_times function exported' );

