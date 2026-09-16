#!/usr/bin/env python3
"""Atheris fuzz harness for fickling's pickle decompiler.

Ports the ORIGINAL mayhemheroes harness (fuzz/fuzz_pickle_decompiler.py @
db75ac2b01e763ebb405cff7f761023b3c6a00aa, target `fuzz_pickle_decompiler`): parse
arbitrary bytes as a pickle stream with fickling's Pickled.load, catching only
ValueError as the library's own documented guard against adversarial input. At this
vintage `fickling.pickle.Pickled` (module `fickle` and `fickling.exception` do not
exist yet — those are later renames/additions) has no decompilation-specific guard,
so this intentionally does NOT call `.ast` or catch the wider exception set the
current live harness does; widening the catch here would mask the very defect this
branch exists to reproduce. Atheris instruments the fickling modules at import so
libFuzzer gets coverage feedback.

The harness sets no timer of its own: a hanging input is a finding, bounded by the
runner (libFuzzer's -timeout / Mayhem's per-exec Mayhemfile timeout), not swallowed
here.

Run modes (driven by the compiled launcher `fuzz_pickle_decompiler` /
`-standalone`):
  * fuzzing      — `python3 fuzz_pickle_decompiler.py [libFuzzer args]`
  * single input — `python3 fuzz_pickle_decompiler.py <file>` (runs it once)
"""
import sys

import atheris

with atheris.instrument_imports():
    from fickling.pickle import Pickled


@atheris.instrument_func
def TestOneInput(data):
    try:
        Pickled.load(data)
    except ValueError:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
