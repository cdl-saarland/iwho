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

## Maturity

This is a research prototype, expect things to break!


## Installation

These steps are for installing IWHO on its own. If you install IWHO as part of
AnICA, follow the steps there instead of the ones here. In particular, AnICA
and IWHO should use the same virtual python environment.

Make sure that you have `llvm-mc` on your path (most likely by installing [LLVM](https://llvm.org/)).
It is used to handle basic instruction (dis)assembly tasks.
Furthermore, you need a python3 setup with the `venv` standard module available.

1. Get the repository and its submodule(s):
    ```
    git clone <repo> iwho
    cd iwho
    ```
2. Set up the virtual environment for IWHO and install python dependencies and
   the IWHO package itself there:
   ```
   ./setup_venv.sh
   ```
   Whenever you run IWHO commands from a shell, you need to have activated
   the virtual environment in this shell before:
   ```
   source ./env/iwho/bin/activate
   ```
3. Download the uops.info xml file:
   ```
   ./inputs/uops_info/fetch_xml.sh
   ```
   Extract the InsnSchemes from the xml file:
   ```
   ./build_schemes.sh
   ```
4. Run the tests:
   ```
   ./tests/test_iwho.py
   ```


## Usage

example

iwho-predict

playground


## Generating Documentation

The API documentation can be built with [pdoc3](https://pdoc3.github.io/pdoc/).
After installing pdoc3 (`pip install pdoc3`) in the virtual environment, run the following command to generate html documentation in the `html` directory:
```
pdoc --html iwho --force
```

## Getting Throughput Predictors

There are a number of convenience scripts to obtain and install several basic block throughput predictors for use with IWHO in the subdirectories of the `predictors` directory (`get.sh`).

For Ithemal, there is a submodule instead of a getter script since we use a modified version of the original docker container.
We added an [RPyC](https://rpyc.readthedocs.io/en/latest/)-based interface to query into the container for throughputs and fixed some of the build scripts in the container that were affected by bit rot.

If you want to use the Ithemal docker container for throughput predictions with IWHO, you therefore need to fetch the corresponding submodule:
```
git submodule update --init --recursive
```
Then build and start the docker container (this requires sudo (the scripts query where necessary), a running docker service, and some time):
```
cd ./predictors/ithemal/
./build.sh
./start.sh
```

You can stop the ithemal docker container again with the following script:
```
./stop.sh
```

## Configuration

Possible entries (duplicates are allowed):
  - `{"kind": "no_cf"}`: only instruction schemes that do not affect control flow
  - `{"kind": "with_measurements", "archs": ["SKL", ...]}`: only instruction schemes for which measurements are available for all of the given microarchitectures
  - `{"kind": "only_mnemonics", "mnemonics": ["add", ...]}`: only instruction schemes with one of the specified mnemonics
  - `{"kind": "blacklist", "file_path": "./path/to/schemes.csv"}`: only instruction schemes that are not in the specified file
  - `{"kind": "whitelist", "file_path": "./path/to/schemes.csv"}`: only instructions that are in the specified file



TODO add a MANIFEST.in
