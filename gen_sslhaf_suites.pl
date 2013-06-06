#!/usr/bin/perl

use strict;

my %ssl2_suites;
my %tls_suites;

while (<>) {
    chomp;
    s/\r//g;

    if ($_ eq "") {
        next;
    }

    if (substr($_, 0, 1) eq "\#") {
        next;
    }

    my ($comment, $label, $id, $key_size, $group) = /^(\#)?([^,]+),([^,]+),([^,]+),(.+)$/;

    $group =~ s/-/_/;

    my %description = ( 'label' => $label, 'id' => $id, 'key_size' => $key_size);

    if ($group eq 'SSL_2_0') {
        $ssl2_suites{$id} = \%description;
    } else {
        if (hex($id) & 0xff0000) {
            next;
        }

        $tls_suites{$id} = \%description;
    }
}

my $ssl2_description_rows = "";
my $ssl2_lookup_cases = "";
my $counter = 0;

foreach my $id (sort(keys(%ssl2_suites))) {
    my $description = $ssl2_suites{$id};
    my $buf;

    $buf = sprintf(
"    { \"%s\", %s, %d },\n",
$description->{'label'}, $description->{'id'},
$description->{'key_size'});

    $ssl2_description_rows .= $buf;

    $buf = sprintf(
"        case %s:\n" .
"            return &sslhaf_ssl2_suites[%d];\n",
$description->{'id'}, $counter);

    $ssl2_lookup_cases .= $buf;

    $counter++;
}

my $tls_description_rows = "";
my $tls_lookup_cases = "";
$counter = 0;

foreach my $id (sort(keys(%tls_suites))) {
    my $description = $tls_suites{$id};
    my $buf;

    $buf = sprintf(
"    { \"%s\", %s, %d },\n",
$description->{'label'}, $description->{'id'},
$description->{'key_size'});

    $tls_description_rows .= $buf;

    $buf = sprintf(
"        case %s:\n" .
"            return &sslhaf_tls_suites[%d];\n",
$description->{'id'}, $counter);

    $tls_lookup_cases .= $buf;

    $counter++;
}


printf(<<EOT
/*

libsslhaf: For passive SSL fingerprinting

 | THIS PRODUCT IS NOT READY FOR PRODUCTION USE. DEPLOY AT YOUR OWN RISK.

Copyright (c) 2009-2012, Qualys, Inc.
Copyright (c) 2012-2013, Network Box Corporation, Ltd.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

* Neither the name of the Qualys, Inc. nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "sslhaf.h"

#include <stdint.h>



static const sslhaf_suite_t sslhaf_suite_unknown = {
    "UNKNOWN", 0xffffffff, 0 };

static const sslhaf_suite_t sslhaf_ssl2_suites[] = {
%s};

static const sslhaf_suite_t *sslhaf_get_ssl2_suite(uint32_t id) {
    switch (id) {
%s    };

    return &sslhaf_suite_unknown;
}

static const sslhaf_suite_t sslhaf_tls_suites[] = {
%s};

static const sslhaf_suite_t *sslhaf_get_tls_suite(uint32_t id) {
    switch (id) {
%s    };

    return &sslhaf_suite_unknown;
}

const sslhaf_suite_t *sslhaf_get_suite(uint32_t id) {
    if (id & 0xff0000)
        return sslhaf_get_ssl2_suite(id);

    return sslhaf_get_tls_suite(id);
}
EOT
,
$ssl2_description_rows,
$ssl2_lookup_cases,
$tls_description_rows,
$tls_lookup_cases);

