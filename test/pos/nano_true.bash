#!/bin/bash

set -ex

test_name="$(basename -s .bash $0)"
${srcdir}/pos -- check-$test_name
