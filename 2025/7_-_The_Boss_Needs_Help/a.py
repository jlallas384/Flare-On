from idaapi import *

from idautils import *

tainters = [0x7FF675B4A3AC,0x7FF675B4A3B0,0x7FF675B4A3B4]
rsp_reg = ida_idp.str2reg("rsp")
rbp_reg = ida_idp.str2reg("rbp")

def unsigned_to_signed_64bit(x: int) -> int:
    if x >= 2**63:
        return x - 2**64
    return x

def do_func(func):

    tainted_regs = [0] * 100
    tainted_stack = [0] * 600000
    OFFSET = 100000
    
    def is_tainted(op: op_t):
        if op.type == o_reg:
            return tainted_regs[op.reg]
        dis_addr = unsigned_to_signed_64bit(op.addr)
        if op.type == o_displ and op.reg in (rsp_reg, rbp_reg) and dis_addr + OFFSET < len(tainted_stack) and dis_addr + OFFSET >= 0:
            return tainted_stack[dis_addr + OFFSET]
        if op.type == o_mem and op.addr in tainters:
            return True
        return False

    def do_taint(op: op_t):
        if op.type == o_reg:
            tainted_regs[op.reg] = 1
        dis_addr = unsigned_to_signed_64bit(op.addr)
        if op.type == o_displ and op.reg in (rsp_reg, rbp_reg):
            tainted_stack[dis_addr + OFFSET] = 1
        
    def remove_taint(op: op_t):
        if op.type == o_reg:
            tainted_regs[op.reg] = 0
        dis_addr = unsigned_to_signed_64bit(op.addr)
        if op.type == o_displ and op.reg in (rsp_reg, rbp_reg):
            tainted_stack[dis_addr + OFFSET] = 0

    def do(insn):
        tainted_insn = False
        if insn.itype == NN_mov:
            if is_tainted(insn.Op2):
                do_taint(insn.Op1)
                tainted_insn = True
            else:
                remove_taint(insn.Op1)
        elif insn.itype == NN_lea:
            if not is_tainted(insn.Op2):
                remove_taint(insn.Op1)
        elif insn.itype == NN_xor and insn.Op1.type == o_reg and insn.Op2.type == o_reg and insn.Op1.reg == insn.Op2.reg:
            remove_taint(insn.Op1)
        elif insn.itype in (NN_call, NN_callni, NN_callfi):
            tainted_regs[ida_idp.str2reg("rax")] = 0
            tainted_regs[ida_idp.str2reg("eax")] = 0
        else:
            for op in insn.ops:
                tainted_insn |= is_tainted(op)
            if tainted_insn:
                for op in insn.ops:
                    do_taint(op)

        return tainted_insn
    
    addr = func.start_ea
    while addr < func.end_ea:
        insn = DecodeInstruction(addr)
        if do(insn):
            patch_bytes(addr, b'\x90' * insn.size)
        addr += insn.size

for f_ea in Functions():
    func = get_func(f_ea)
    try:
        do_func(func)
    except:
        pass
