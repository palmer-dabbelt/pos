#!/bin/bash

set -ex

diff -u <(${srcdir}/pos -- check-static_argv) - << EOF
check-static_argv
EOF
