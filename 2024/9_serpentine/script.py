from idaapi import *
from z3 import *
from idc import *
from idautils import DecodeInstruction

def make(x):
    return BitVecVal(x, 64)

def add(prev, now):
    return simplify(make(now) - make(prev)).as_long()

def sub(prev, now):
    return simplify(make(prev) - make(now)).as_long()

def xor(prev, now):
    return simplify(make(prev) ^ make(now)).as_long()

def match_ins(addr, *ins):
    try:
        idx = 0
        while idx < len(ins):
            if DecodeInstruction(addr).itype != ins[idx]:
                return False
            addr = next_head(addr)
            idx += 1
        return True
    except AttributeError:
        return False

def step_until(*ins):
    dump = []
    while True:
        wait_for_next_event(WFNE_SUSP, -1)    
        addr = get_reg_value("rip") 
        refresh_debugger_memory()
        if DecodeInstruction(addr).itype in ins:
            break
        dump.append(GetDisasm(addr))
        request_step_into()
        run_requests()
    return dump


def get_bytes_int(addr, size):
    refresh_debugger_memory()
    return int.from_bytes(get_bytes(addr, size), 'little')


s = "ABCDGFEHIJKLMNOPQRSTUVWXabcdefYZ"

for it in range(32):
    var = f'e{it}'

    step_until(NN_mul)
    multiplier = get_bytes_int(get_reg_value('rsp'), 4)
    rax = get_reg_value('rax')

    eq = f'(make({s.index(chr(rax))}) * {hex(multiplier)})'

    def make_eq(var, res):
        return f'{var} = {res}'

    with open('ff.txt', 'a') as f:
        f.write(f'{make_eq(var, eq)}\n')

    prev = rax * multiplier

    request_step_into()
    run_requests()

    def determine(dump):
        if any(x.startswith('sub') for x in dump):
            return sub, '-'
        shls = [x.split(', ')[1] for x in dump if x.startswith('shl')]
        shls = [int(x if x[-1] != 'h' else x[:-1]) for x in shls]
        if shls[-1] == 8:
            shls.pop()
        if all(shls[i] <= shls[i + 1] for i in range(len(shls) - 1)):
            return xor, '^'
        return add, '+'


    for i in range(7):
        wait_for_next_event(WFNE_SUSP, -1)
        dump = step_until(NN_mul)
        multiplier = get_bytes_int(get_reg_value('rsp'), 4)
        rax = get_reg_value('rax')
        refresh_debugger_memory()
        wait_for_next_event(WFNE_SUSP, -1)
        step_until(NN_add, NN_sub, NN_xor)

        wait_for_next_event(WFNE_SUSP, -1)
        addr = get_reg_value("rip")
        reg_name = get_reg_name(get_operand_value(addr, 0), 8)
        now = get_reg_value(reg_name)
        op, cop = determine(dump)

        with open('ff.txt', 'a') as f:
            rhs = hex(op(prev, now))
            eq = make_eq(var, f'{var} {cop} {rhs}')
            f.write(f'{eq}\n')

        ins_op = DecodeInstruction(addr).itype
        rhs = f'(make({s.index(chr(rax))}) * {hex(multiplier)})'
        if ins_op == NN_add:
            ins_cop = '+'
        elif ins_op == NN_sub:
            ins_cop = '-'
        else:
            ins_cop = '^'
        
        with open('ff.txt', 'a') as f:
            eq = f'{var} {ins_cop} {rhs}'
            f.write(f'\n{make_eq(var, eq)}\n')
        request_step_into()
        run_requests()
        refresh_debugger_memory()
        wait_for_next_event(WFNE_SUSP, -1)
        prev = get_reg_value(reg_name)

    refresh_debugger_memory()
    wait_for_next_event(WFNE_SUSP, -1)

    dump = step_until(NN_sub)
    op, cop = determine(dump)

    refresh_debugger_memory()
    wait_for_next_event(WFNE_SUSP, -1)

    addr = get_reg_value('rip')
    insn = DecodeInstruction(addr)
    displacement = get_operand_value(addr, 0)
    reg = insn.Op1.reg
    reg_val = get_reg_value(get_reg_name(reg, 8))
    now = int.from_bytes(get_bytes(reg_val + displacement, 8), byteorder='little')

    if now == prev:
        request_step_into()
        run_requests()
        while True:
            dump = step_until(NN_sub)
            if sum(x.startswith("shl") and x.endswith("8") for x in dump) == 1:
                break
            request_step_into()
            run_requests()
        op, cop = sub, '-'

        refresh_debugger_memory()
        wait_for_next_event(WFNE_SUSP, -1)

        addr = get_reg_value('rip')
        insn = DecodeInstruction(addr)
        displacement = get_operand_value(addr, 0)
        reg = insn.Op1.reg
        reg_val = get_reg_value(get_reg_name(reg, 8))
        now = int.from_bytes(get_bytes(reg_val + displacement, 8), byteorder='little')
        with open('ff.txt', 'a') as f:
            rhs = hex(op(prev, now))
            eq = make_eq(var, f'{var} {cop} {rhs}')
            f.write(f'{eq}\n')

    else:
        with open('ff.txt', 'a') as f:
            rhs = hex(op(prev, now))
            eq = make_eq(var, f'{var} {cop} {rhs}')
            f.write(f'{eq}\n')

    prev = now

    step_until(NN_test)
    refresh_debugger_memory()
    wait_for_next_event(WFNE_SUSP, -1)
    addr = get_reg_value('rip')

    insn = DecodeInstruction(addr)
    reg = insn.Op1.reg
    reg_name = get_reg_name(reg, 8)
    now = get_reg_value(reg_name)

    with open('ff.txt', 'a') as f:
        rhs = hex(sub(prev, now))
        eq = make_eq(var, f'{var} - {rhs}')
        f.write(f'{eq}\n\n')

    set_reg_val(reg_name, 0)