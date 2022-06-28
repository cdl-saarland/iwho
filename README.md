# IWHO - Instructions With HOles

IWHO is a python library for representing machine instructions.
Its focus is on enabling easy instantiations of instructions with parameters.

The representation of an ISA in IWHO provides a set of **instruction schemes**, which are, effectively, instructions with holes instead of operands.
These holes are annotated with operands that can be used there in an instantiation of the instruction scheme.
A key feature of IWHO (which distinguishes it, e.g., from a similarly used combination of [capstone](https://www.capstone-engine.org/) and [keystone](https://www.keystone-engine.org/)) is that it provides a closed (dis)assembly loop:
You can instantiate a list of IWHO instruction schemes with allowed operands, assemble it to a hex string, and disassemble this hex string to an equal list of instruction scheme instantiations.

Other use-cases include:
- Disassemble a hex string into a sequence of instructions, query their instruction schemes, instantiate them with (partially) changed operands, and dump the result as assembly or hex string.
- Do the same with an assembly string.
- Generate (test) inputs for instruction throughput predictors/microarchitectural code analyzers.

Under the hood, IWHO (dis)assembles instructions using LLVM's llvm-mc tool.
Disassembled instructions are matched to registered instruction schemes via a simple parser.

IWHO is **not** suitable for use as a full (dis)assembler framework since, e.g., relocations as memory operands are not represented in a semantically meaningful way.

Currently, only the x86-64 ISA is implemented, with instruction schemes extracted from [uops.info](https://uops.info/).


## Installation

TODO

## Usage

TODO


## Configuration

Possible entries (duplicates are allowed):
  - `{"kind": "no_cf"}`: only instruction schemes that do not affect control flow
  - `{"kind": "with_measurements", "archs": ["SKL", ...]}`: only instruction schemes for which measurements are available for all of the given microarchitectures
  - `{"kind": "only_mnemonics", "mnemonics": ["add", ...]}`: only instruction schemes with one of the specified mnemonics
  - `{"kind": "blacklist", "file_path": "./path/to/schemes.csv"}`: only instruction schemes that are not in the specified file
  - `{"kind": "whitelist", "file_path": "./path/to/schemes.csv"}`: only instructions that are in the specified file



TODO add a MANIFEST.in
