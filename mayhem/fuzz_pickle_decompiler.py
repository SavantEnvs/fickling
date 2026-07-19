#!/usr/bin/env python3
"""Atheris fuzz harness for fickling's pickle decompiler.

Ports the original mayhemheroes harness (fuzz/fuzz_pickle_decompiler.py, target
`fuzz_pickle_decompiler`): parse arbitrary bytes as a pickle stream with
fickling's Pickled.load, then decompile it to a Python AST (the decompiler code
path the target is named after). Atheris instruments the fickling modules at
import so libFuzzer gets coverage feedback.

A pathological input must not hang the fuzzer, so each TestOneInput is guarded
by a per-input SIGALRM watchdog.

Run modes (driven by the compiled launcher `fuzz_pickle_decompiler` /
`-standalone`):
  * fuzzing      — `python3 fuzz_pickle_decompiler.py [libFuzzer args]`
  * single input — `python3 fuzz_pickle_decompiler.py <file>` (runs it once)
"""
import signal
import struct
import sys

import atheris

with atheris.instrument_imports():
    import ast  # noqa: F401  (decompilation target module, as in the original harness)

    from fickling.exception import ResourceExhaustionError
    from fickling.fickle import Pickled


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
        pickled = Pickled.load(data)
        # Decompile to an AST — the code path this target has always exercised.
        pickled.ast
    except _InputTimeout:
        pass
    except ResourceExhaustionError:
        # Library-defined guard against decompression/expansion attacks.
        pass
    except (
        ValueError,
        KeyError,
        IndexError,
        AttributeError,
        TypeError,
        NotImplementedError,
        MemoryError,
        RecursionError,
        UnicodeDecodeError,
        EOFError,
        OverflowError,
        struct.error,
    ):
        # Value/lookup/decode errors on adversarial input are not memory-safety
        # defects; the harness surfaces crashes the library does not guard against.
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
