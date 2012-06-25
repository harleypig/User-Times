#!/usr/bin/perl

use strict;
use warnings;

use DBI;
use Data::Dump 'dump';

my $dbh = DBI->connect( 'DBI:Sys:' )
  or die 'Unable to connect: ', $DBI::errstr;

my $st = $dbh->prepare( 'select * from logins' )
  or die 'Unable to prepare: ', $dbh->errstr;

$st->execute;

my $logins = $st->fetchall_hashref( 'timestamp' )
  or die 'Unable to fetch: ', $st->errstr;

print dump $logins;
