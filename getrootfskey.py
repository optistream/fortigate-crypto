from argparse import ArgumentParser

import binascii
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import *

parser = ArgumentParser("Get FortiGate rootfs encryption seed")
parser.add_argument("target_binary", help="Target binary path")
options = parser.parse_args()

fdesc = open(options.target_binary, 'rb')
loc_db = LocationDB()
cont = Container.from_stream(fdesc, loc_db)
machine = Machine(cont.arch)

print(f"Architecture: {cont.arch}")
ret_val_reg = None
arg_val_reg = None
match cont.arch:
    case "x86_64":
        ret_val_reg = machine.mn.regs.RAX
        arg_val_reg = machine.mn.regs.RSI
    case "aarch64l":
        ret_val_reg = machine.mn.regs.X0
        arg_val_reg = machine.mn.regs.X1
        
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
addr = loc_db.get_name_offset("fgt_verifier_pub_key")
asmcfg = mdis.dis_multiblock(addr)
lifter = machine.lifter_model_call(mdis.loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

symb = SymbolicExecutionEngine(lifter)
all_seeds = list()
while True:
    irblock = ircfg.get_block(addr)
    if irblock is None:
        break

    addr = symb.eval_updt_irblock(irblock, step=False)
    if ret_val_reg in symb.symbols.symbols_id:
        reg_expr = symb.symbols.symbols_id[ret_val_reg]
        if reg_expr.is_function_call():
            target = reg_expr.args[0]
            target_func = loc_db.get_offset_location(target.arg)
            target_func = list(loc_db.get_location_names(target_func))[0]
            if target_func == "sha256_update":
                all_seeds.append(symb.symbols.symbols_id[arg_val_reg].arg)

seed_addr = min(all_seeds)
print(f"Seed address: {hex(seed_addr)}")

seed_data = cont.executable.get_virt().get(seed_addr, seed_addr + 32)
seed_data = binascii.hexlify(seed_data).upper()
print(f"Extracted seed: {seed_data}")
