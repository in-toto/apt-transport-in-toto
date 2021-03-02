#!/usr/bin/python3
"""
<Program Name>
  measure_coverage.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  December 21, 2018.

<Purpose
  Shim to setup code coverage measurement for a Python script executed
  in a subprocess.

  Requires an environment variable COVERAGE_PROCESS_START that points to the
  .coveragerc file that should be used.

  This is an alternative to performing coverage setup using`sitecustomize.py`
  or `.pth` file as suggested in:
  https://coverage.readthedocs.io/en/coverage-4.2/subprocess.html


  Usage:
      python measure_coverage.py <path/to/python/script>


"""
import sys
import coverage

# Setup code coverage measurement (will look for COVERAGE_PROCESS_START envvar)
coverage.process_startup()

# The first argument must be the actual executable
exectuable = sys.argv[1]

# Patch sys.argv so that the executable thinks it was called directly
sys.argv = [exectuable]

# Execute executable in this process measuring code coverage
with open(exectuable) as f:
    code = compile(f.read(), exectuable, "exec")
    exec(code)
