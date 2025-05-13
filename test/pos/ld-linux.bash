#!/bin/bash

set -ex

diff -u <(${srcdir}/pos -- /lib64/ld-linux-x86-64.so.2) <(/lib64/ld-linux-x86-64.so.2)
