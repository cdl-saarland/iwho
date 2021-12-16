TODO write

## Configuration

Possible entries (duplicates are allowed):
  - `{"kind": "no_cf"}`: only instruction schemes that do not affect control flow
  - `{"kind": "with_measurements", "archs": ["SKL", ...]}`: only instruction schemes for which measurements are available for all of the given microarchitectures
  - `{"kind": "only_mnemonics", "mnemonics": ["add", ...]}`: only instruction schemes with one of the specified mnemonics
  - `{"kind": "blacklist", "file_path": "./path/to/schemes.csv"}`: only instruction schemes that are not in the specified file
  - `{"kind": "whitelist", "file_path": "./path/to/schemes.csv"}`: only instructions that are in the specified file



TODO add a MANIFEST.in
