from idaapi import *
from idautils import *

import struct

jump_table = 0x0000000140C687B8
base = 0x140000000

def get_jump_start(index):
    addr = struct.unpack('<I', get_bytes(jump_table + 4 * index, 4))[0] + 0x140000000
    return addr

totals = 90780 + 1

def do_at(index):
    addr = get_jump_start(index)
    itr = 0
    while itr < 50:
        ins = DecodeInstruction(addr)
        if ins.itype == NN_jl:
            break
        addr += ins.size
        itr += 1
    
    if itr >= 50:
        assert False

    itr = 0
    got = []
    while itr < 100:
        ins = DecodeInstruction(addr)
        addr += ins.size
        if ins.itype == NN_jmp:
            break
        if ins.itype == NN_cmp:
            character = ins.Op2.value
            jz_instr = DecodeInstruction(addr)

            addr += jz_instr.size

            if jz_instr.itype != NN_jz:
                raise AssertionError("fail")

            assert jz_instr.itype == NN_jz
            to = jz_instr.Op1.addr

            mov_instr = DecodeInstruction(to)
            if mov_instr.itype != NN_mov:
                raise AssertionError("fail")

            assert mov_instr.itype == NN_mov
            next_state = mov_instr.Op2.value

            got.append((character, next_state))
        itr += 1

    if itr >= 100:
        assert False
    return got

fails = 0
graph = []
for i in range(totals):
    try:
        graph.append([])
        result = do_at(i)
        graph[-1] += result
    except:
        fails += 1

print('fails', fails)
import json
with open('graph.json', 'w') as f:
    f.write(json.dumps(graph))