#!/usr/bin/env python3
"""Atheris fuzz harness for fickling's pickle decompiler.

Ports the original mayhemheroes harness (fuzz/fuzz_pickle_decompiler.py, target
`fuzz_pickle_decompiler`): parse arbitrary bytes as a pickle stream with
fickling's Pickled.load, then decompile it to a Python AST (the decompiler code
path the target is named after). Atheris instruments the fickling modules at
import so libFuzzer gets coverage feedback.

The harness sets no timer of its own: a hanging input is a finding, bounded by
the runner (libFuzzer's -timeout / Mayhem's per-test timeout), not swallowed here.

Run modes (driven by the compiled launcher `fuzz_pickle_decompiler` /
`-standalone`):
  * fuzzing      — `python3 fuzz_pickle_decompiler.py [libFuzzer args]`
  * single input — `python3 fuzz_pickle_decompiler.py <file>` (runs it once)
"""
import struct
import sys

import atheris

with atheris.instrument_imports():
    import ast  # noqa: F401  (decompilation target module, as in the original harness)

    from fickling.exception import ResourceExhaustionError
    from fickling.fickle import Pickled


@atheris.instrument_func
def TestOneInput(data):
    try:
        pickled = Pickled.load(data)
        # Decompile to an AST — the code path this target has always exercised.
        pickled.ast
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


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
