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

A pathological input must not hang the fuzzer, so each TestOneInput is guarded by a
per-input SIGALRM watchdog (an addition over the original, which relied on Mayhem's
own run-level timeout).

Run modes (driven by the compiled launcher `fuzz_pickle_decompiler` /
`-standalone`):
  * fuzzing      — `python3 fuzz_pickle_decompiler.py [libFuzzer args]`
  * single input — `python3 fuzz_pickle_decompiler.py <file>` (runs it once)
"""
import signal
import sys

import atheris

with atheris.instrument_imports():
    from fickling.pickle import Pickled


class _InputTimeout(Exception):
    pass


def _alarm(signum, frame):
    raise _InputTimeout()


signal.signal(signal.SIGALRM, _alarm)
_PER_INPUT_SECONDS = 5


@atheris.instrument_func
def TestOneInput(data):
    signal.setitimer(signal.ITIMER_REAL, _PER_INPUT_SECONDS)
    try:
        Pickled.load(data)
    except _InputTimeout:
        pass
    except ValueError:
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
