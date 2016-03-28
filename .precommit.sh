#!/usr/bin/env bash
echo [flake8]
find . -maxdepth 1 -name \*.py -exec flake8 --max-complexity 9 {} \; 2>&1 | grep -E '^\./.+' 1>&2
flake=$?
echo [pylint]
find . -maxdepth 1 -name \*.py -exec pylint --disable=I --msg-template='./{path}:{line}:{column}: {msg_id} {msg} ({symbol})' {} \; 2>&1 | grep -E '^\./.+' 1>&2
pylint=$?
echo [FINISH]
# "1" for grep's "not found"
if [ $flake -ne 1 ] || [ $pylint -ne 1 ]; then
  exit 1
fi
