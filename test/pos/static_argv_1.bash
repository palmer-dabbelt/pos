#!/bin/bash

set -ex

diff -u <(${srcdir}/pos -- check-static_argv arg1) - << EOF
check-static_argv
arg1
EOF
