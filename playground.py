#!/usr/bin/env python3

import sys

import iwho.iwho as iwho
import iwho.x86 as x86


def main():
    from iwho.iwho_utils import parse_args_with_logging
    import argparse
    argparser = argparse.ArgumentParser(description="Interactive playground for using instructions with holes (iwho)")
    argparser.add_argument("-b", "--bytes", metavar="HEXSTR", default=None, help="decode instructions from the bytes represented by the specified hex string")

    argparser.add_argument("-a", "--asm", metavar="ASMSTR", default=None, help="load instructions from the specified asm string")

    argparser.add_argument("-i", "--interactive", action="store_true", help="after loading instructions, open an interactive mode (IPython if available)")

    argparser.add_argument("-s", "--insnschemes", metavar="JSON", required=True, help="use instruction schemes from this json file")

    args = parse_args_with_logging(argparser, "warning")
    # TODO stdin

    import json

    with open(args.insnschemes, 'r') as infile:
        scheme_data = json.load(infile)

    ctx = x86.Context()
    ctx.fill_from_json_dict(scheme_data)


    insns = []
    if args.bytes is not None:
        insns += ctx.decode_insns(args.bytes)

    if args.asm is not None:
        insns += ctx.parse_asm(args.asm)

    print("loaded instructions:")
    for ii in insns:
        print(f"  {ii}  # scheme: {ii.scheme}")

    if not args.interactive:
        sys.exit(0)

    def hex2insns(hex_str):
        return ctx.decode_insns(hex_str)

    def asm2insns(asm_str):
        return ctx.parse_asm(asm_str)

    def insns2hex(insns):
        return ctx.encode_insns(insns)

    print("available variables:")
    print("  - the iwho Context as `ctx`")
    print("  - the argument InsnInstances as `insns`")
    print("available functions:")
    print("  - hex2insns(hex_str: str) -> List[InsnInstance]")
    print("  - asm2insns(asm_str: str) -> List[InsnInstance]")
    print("  - insns2hex(insns: List[InsnInstance]) -> str")

    use_ipython = False
    try:
        from IPython import embed
        use_ipython = True
    except ImportError:
        pass

    if use_ipython:
        print("starting IPython...")
        embed()
    else:
        print("starting interactive python shell...")
        import readline
        import code
        variables = {**globals(), **locals()}
        shell = code.InteractiveConsole(variables)
        shell.interact()


if __name__ == "__main__":
    main()