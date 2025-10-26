from idaapi import *
from idautils import *
from typing import List
import idc

def patch_jumps(func: func_t):
    start = func.start_ea
    end = func.end_ea

    while start < end:
        idc.create_insn(start)
        insn = DecodeInstruction(start)
        if insn.itype == NN_jmpni and insn.Op1.type == o_reg:
            if start + insn.size < end:
                patch_bytes(start, b'\x90' * insn.size)
        if insn.itype == NN_jmp and insn.Op1.addr - insn.ea == insn.size:
                patch_bytes(start, b'\x90' * insn.size)
        start += insn.size

f = get_func(0x7FF7E3884860)

def nop_instr(insn: insn_t):
    patch_bytes(insn.ea, b'\x90' * insn.size)


def encode_call(src_addr, dst_addr):
    rel32 = dst_addr - (src_addr + 5)
    rel_bytes = int(rel32).to_bytes(4, byteorder="little", signed=True)
    return b"\xE8" + rel_bytes

def patch_call_rax(func: func_t):
    insn_stack: List[insn_t, bytes] = [] # (insn_t, bytes representation)
    start = func.start_ea
    end = func.end_ea

    def get_op_value(op: op_t):
        if op.type == o_imm:
            return op.value
        if op.type == o_mem:
            return int.from_bytes(get_bytes(op.addr, 8), 'little')
        assert False

    while start < end:
        insn = DecodeInstruction(start)
        print(hex(start))
        insn_bs = get_bytes(start, insn.size)
        insn_size = insn.size
        if insn.itype == NN_callni and insn.Op1.type == o_reg and insn.Op1.reg == 0:
            to_move = []
            try:
                while len(insn_stack):
                    cinsn_tup = insn_stack.pop()
                    cinsn = cinsn_tup[0]
                    if cinsn.itype == NN_add and cinsn.Op1.type == o_reg and cinsn.Op2.type == o_reg:
                        nop_instr(cinsn)
                        assert len(insn_stack) >= 2
                        op1 = insn_stack.pop()[0]
                        op2 = insn_stack.pop()[0]
                        print(hex(op1.ea))
                        print(hex(op2.ea))
                        assert op1.itype == NN_mov
                        assert op2.itype == NN_mov

                        call_addr = (get_op_value(op1.Op2) + get_op_value(op2.Op2)) & 0xffffffffffffffff
                        nop_instr(op1)
                        nop_instr(op2)
                        nop_instr(insn)
                        start_patch = op2.ea

                        for tinsn in to_move:
                            patch_bytes(start_patch, tinsn)
                            start_patch += len(tinsn)
                        patch_bytes(start_patch, encode_call(start_patch, call_addr))
                        start = start_patch + 5
                        break
                    else:
                        to_move.append(cinsn_tup[1])
            except:
                start += insn_size
        else:
            insn_stack.append((insn, insn_bs))
            start += insn_size

def get_function_except_ret(addr):
    bs = b''
    while True:
        insn = DecodeInstruction(addr)
        if insn.itype == NN_retn:
            return bs
        bs += get_bytes(addr, insn.size)
        addr += insn.size
        
def patch_offset_calls(func: func_t):
    start = func.start_ea
    end = func.end_ea
    while start < end:
        insn = DecodeInstruction(start)
        if insn.itype == NN_call:
            addr = insn.Op1.addr
            cinsn = DecodeInstruction(addr)
            if cinsn.itype == NN_mov and cinsn.Op1.reg == 0 and cinsn.Op2.reg == 1:
                nw = get_function_except_ret(addr)

                if get_bytes(start + insn.size, max(0, len(nw) - insn.size)) == b'\x90' * (max(0, len(nw) - insn.size)):
                    print(hex(start))
                    patch_bytes(start, nw)
                    start += len(nw)
                    print('opt')
                else:
                    start += insn.size
            else:
                start += insn.size
        else:
            start += insn.size

st = set()

def do_func(func: func_t):
    patch_jumps(func)
    patch_call_rax(func)
    start = func.start_ea
    end = func.end_ea
    st.add(start)
    return
    while start < end:
        insn = DecodeInstruction(start)
        
        if insn.itype == NN_call:
            addr = insn.Op1.addr
            if addr not in st:
                print('recursing to', hex(addr))
                add_func(addr)
                do_func(get_func(addr))

        start += insn.size

#f = get_func(0x7FF7F2767160)
f = get_func(0x140074860)
do_func(f)