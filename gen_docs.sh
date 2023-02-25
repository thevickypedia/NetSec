#!/usr/bin/env bash
# `set -e` stops the execution of a script if a command or pipeline has an error.
# This is the opposite of the default shell behaviour, which is to ignore errors in scripts.
set -e
rm -rf docs
mkdir docs
mkdir -p docs_gen/_static  # creates a _static folder if unavailable
cp README.md docs_gen && cd docs_gen && make clean html && mv _build/html/* ../docs && rm README.md
touch ../docs/.nojekyll