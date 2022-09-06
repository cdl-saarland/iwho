This directory is for storing the instruction schemes for supported ISAs in
json format.

Since json parsing is slow, iwho also caches Context objects as .pickle files
in this directory. Delete the .pickle files to invalidate the caches.

The `x86_uops_info.json` and `x86_uops_info_features.json` files are extracted
from the uops.info xml. Use `./inputs/uops_info/fetch_xml.sh` and
`./build_schemes.sh` (from the iwho top-level directory) to regenerate them
with a newer version of the xml.
