#!/usr/bin/env perl

# Copyright © 2021-2022 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

no lib '.';  # CVE-2016-1238

use strict;
use warnings;
use v5.14;

use English qw(-no_match_vars);
use File::Temp ();
use FindBin ();
use autodie;

use Test::More tests => 3;

use IPC::System::Simple ();

sub slurp
{
    my ($path) = @_;
    local $RS = undef;
    open my $fh, '<', $path;
    $_ = <$fh>;
    close $fh;
    return $_;
}

chdir "$FindBin::Bin/..";
my $readme = slurp('README');

sub extract_output
{
    my ($cmd) = @_;
    $readme =~ m/\n   [\$] \Q$cmd\E\n((?:(   [^\$].*)?\n)+)/
        or die "cannot extract output for '$cmd' from README";
    $_ = $1;
    chomp;
    s/^   //gm;
    return $_;
}

sub capture_script
{
    my ($cmd) = @_;
    local $ENV{TERM} = 'ansi';
    $_ = IPC::System::Simple::capturex(qw(script -q -c ), $cmd, '/dev/null');
    s/\A\r|\r(?=\n)|\r\e\[K//g;
    return $_;
}

my $less_cmd = 'less -FX hello.c';
my $readme_apparent_code = extract_output($less_cmd);
my $actual_apparent_code = capture_script($less_cmd);
cmp_ok($actual_apparent_code, 'eq', $readme_apparent_code, $less_cmd);

my $run_cmd = 'gcc -Wall hello.c -o hello && ./hello';
my $readme_run_output = extract_output($run_cmd);
my $tmp_exe_fh = File::Temp->new(TEMPLATE => 'hello.XXXXXX', SUFFIX => '.tmp');
close $tmp_exe_fh;
my $tmp_exe_path = $tmp_exe_fh->filename;
my $run_cmd2 = $run_cmd;
$run_cmd2 =~ s/\s\K-Wall\b/-Werror/;
$run_cmd2 =~ s/\bhello(?![.]c)\b/$tmp_exe_path/g;
my $actual_run_output = capture_script($run_cmd2);
cmp_ok($actual_run_output, 'eq', $readme_run_output, $run_cmd2);

my $tmp_c_fh = File::Temp->new(TEMPLATE => 'hello.XXXXXX', SUFFIX => '.tmp.c');
print {$tmp_c_fh} $readme_apparent_code
    or die;
close $tmp_c_fh;
my $tmp_c_path = $tmp_c_fh->filename;
my $run_cmd3 = $run_cmd2;
$run_cmd3 =~ s/\bhello[.]c\b/$tmp_c_path/;
my $apparent_run_output = capture_script($run_cmd3);
cmp_ok($apparent_run_output, 'eq', "Hello world!\n", $run_cmd3);

# vim:ts=4 sts=4 sw=4 et
