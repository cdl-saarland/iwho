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

You can directly interact with the IWHO instruction representations with the
interactive `scripts/playground.py` script.
Run it, with an optional IWHO config (see below) and optionally providing an
input basic block in hex encoding or as assembly, for example:

```
./scripts/playground

./scripts/playground -c configs/iwho/default.json

./scripts/playground -x "c0ffee"

./scripts/playground -a "add rax, rbx; sub rcx, rdx"

./scripts/playground -a ".att_syntax; addq %rbx, %rax; subq %rdx, %rcx"
```

If available, IPython will be used for improved interactivity (run `pip install
ipython` in the virtual environment to install it).
If instructions are provided via arguments, they are loaded, displayed, and
inserted to the `insns` list before starting the interactive session.

The interactive session prints the available variables and functions, which can be used to encode and decode instructions.
You can check the human-readable IWHO representation of the loaded instructions by just typing `insns`.

Once you have set up a predictor registry (see below), you can also use `tool/iwho-predict` to run registered basic block throughput predictors one given basic blocks:

```
iwho-predict -c ./configs/predictors/default.json -a bb.s <pred_key_pattern1> ...

iwho-predict -c ./configs/predictors/default.json -x 'c0ffee' <pred_key_pattern1> ...
```

The positional arguments can be keys from the used predictor registry (see below) or python regex patterns matching one or more of these keys.


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

IWHO is configured with a json file. For an example configuration, see `configs/iwho/default.json`, the default.

The `context_specifier` is a string identifier of the ISA declaration to use.
Currently, only the x86 instruction schemes extracted from uops.info are supported.
If you specify only a prefix of an available context specifier (like `x86`), one of the matching ISA declarations is chosen.

The `filters` entry is a list of filters used to control what instruction schemes from the selected ISA declaration are used.
Possible entries are (duplicates are allowed):
  - `{"kind": "no_cf"}`: only instruction schemes that do not affect control flow
  - `{"kind": "with_measurements", "archs": ["SKL", ...]}`: only instruction schemes for which measurements are available for all of the given microarchitectures
  - `{"kind": "only_mnemonics", "mnemonics": ["add", ...]}`: only instruction schemes with one of the specified mnemonics
  - `{"kind": "blacklist", "file_path": "./path/to/schemes.csv"}`: only instruction schemes that are not in the specified file
  - `{"kind": "whitelist", "file_path": "./path/to/schemes.csv"}`: only instructions that are in the specified file

IWHO also provides an interface to many basic block throughput predictors.
This component is configured with additional json config files:
For an example see `configs/predictors/default.json`:
It specifies how many prediction tasks may be performed concurrently (0 for as many as there are processor cores) and a path to a predictor registry file.
To run predictors, you need to create such a registry file, for example as `configs/predictors/pred_registry.json` to work with the default config.
This predictor registry needs to contain a dictionary that assigns configurations to unique predictor identifiers.
You may copy and adjust entries from `configs/predictors/pred_registry_template.json` to this file, while inserting install-dependent paths to the tools where necessary.

