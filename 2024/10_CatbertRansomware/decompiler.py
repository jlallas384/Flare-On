import sys
from operator import *

class MemRead:
    def __init__(self, addr):
        self.addr = addr
    def __str__(self):
        return f'var_{self.addr}'
    def line(self):
        return self.addr.line()
    
class MemWrite:
    def __init__(self, addr, value):
        self.addr = addr
        self.value = value
    def __str__(self):
        return f'var_{self.addr} = {self.value}'
    def line(self):
        return self.addr.line()
    
class Const:
    def __init__(self, start, value):
        self.value = value
        self.start = start
    def __str__(self):
        return f'{hex(self.value)}'
    def line(self):
        return self.start

def flip(op):
    return {
        '==': '!=',
        '!=': '==',
        '>': '<=',
        '<': '>=',
        '>=': '<',
        '<=': '>',
    }[op]

class BinOp:
    def __init__(self, op, lhs, rhs):
        self.op = op
        self.lhs = lhs
        self.rhs = rhs
    def __str__(self):
        left = f'{self.lhs}'
        right = f'{self.rhs}'
        if type(self.lhs) == BinOp:
            left = f'({left})'
        elif type(self.rhs) == BinOp:
            right = f'({right})'
        return f'{left} {self.op} {right}'
    def line(self):
        return self.lhs.line()
    
class UnconditionalJump:
    def __init__(self, start, target):
        self.target = target
        self.start = start
    def __str__(self):
        return f'goto {hex(self.target)}'
    def line(self):
        return self.start
    
class ConditionalJump:
    def __init__(self, condition, target):
        self.condition = condition
        self.condition.op = flip(self.condition.op)
        self.target = target
    def __str__(self):
        return f'if ({self.condition}) goto {hex(self.target)}'
    def line(self):
        return self.condition.line()

class FnCall:
    def __init__(self, fn, *args):
        self.fn = fn
        self.args = args
    def __str__(self):
        return f'{self.fn}({", ".join(map(str, self.args))})'
    def line(self):
        return min(map(lambda x: x.line(), self.args))
    
def make_bin_op(char_op, op, left, right):
    if type(left) == Const and type(right) == Const:
        return Const(left.line(), op(left.value, right.value))
    return BinOp(char_op, left, right)

def decompile(ins):
    ip = 0
    stk = []
    statements = []
    def pop_two():
        right = stk.pop()
        left = stk.pop()
        return left, right
    
    while ip < len(ins):
        match ins[ip]:
            case 0x1:
                stk.append(Const(ip, int.from_bytes(ins[ip+1:ip+3], byteorder='big')))
                ip += 3
            case 0x6:
                frm, to = pop_two()
                statements.append(MemWrite(frm, to))
                ip += 1
            case 0x5:
                idx = stk.pop()
                stk.append(MemRead(idx))
                ip += 1
            case 0x1e:
                left, right = pop_two()
                stk.append(make_bin_op('<<', lshift, left, right))
                ip += 1
            case 0x1b:
                left, right = pop_two()
                stk.append(make_bin_op('|', or_, left, right))        
                ip += 1   
            case 0x11:
                left, right = pop_two()
                stk.append(make_bin_op('==', eq, left, right))
                ip += 1
            case 0x10:
                target = int.from_bytes(ins[ip+1:ip+3], byteorder='big')
                cond = stk.pop()
                statements.append(ConditionalJump(cond, target))
                ip += 3
            case 0x12:
                left, right = pop_two()
                stk.append(make_bin_op('<', lt, left, right))
                ip += 1
            case 0xd:
                left, right = pop_two()
                stk.append(make_bin_op('*', mul, left, right))
                ip += 1
            case 0x1f:
                left, right = pop_two()
                stk.append(make_bin_op('>>', rshift, left, right))
                ip += 1
            case 0x14:
                left, right = pop_two()
                stk.append(make_bin_op('>', gt, left, right))
                ip += 1
            case 0x1c:
                left, right = pop_two()
                stk.append(make_bin_op('&', and_, left, right))
                ip += 1
            case 0x9:
                left, right = pop_two()
                stk.append(make_bin_op('+', add, left, right))
                ip += 1
            case 0x1d:
                left, right = pop_two()
                stk.append(make_bin_op('%', mod, left, right))
                ip += 1
            case 0x1a:
                left, right = pop_two()
                stk.append(make_bin_op('^', xor, left, right))
                ip += 1
            case 0xe:
                target = int.from_bytes(ins[ip+1:ip+3], byteorder='big')
                statements.append(UnconditionalJump(ip, target))
                ip += 3
            case 0x19:
                statements.append(FnCall('finish', stk.pop()))
                ip += 1
                pass
            case 0x24:
                opr, shift = pop_two()
                stk.append(FnCall('rotl8', opr, shift))
                ip += 1
            case 0x25:
                opr, shift = pop_two()
                stk.append(FnCall('rotr8', opr, shift))
                ip += 1
            case 0x21:
                opr, shift = pop_two()
                stk.append(FnCall('rotr32', opr, shift))
                ip += 1
            case 0x18:
                ip += 1
            case 0x26:
                tp = stk.pop()
                statements.append(FnCall('print', tp))
                ip += 1
            case _:
                print(f'Unknown instruction {hex(ins[ip])}')
                exit(1)
    for s in filter(lambda x: type(x) in [UnconditionalJump, ConditionalJump], statements):
        for i, stmt in enumerate(statements):
            if stmt.line() == s.target:
                s.target = i
                break
    for i, stmt in enumerate(statements):
        print(f'{hex(i)}: {stmt}')

def main():
    if len(sys.argv) != 2:
        print('Usage: python decompiler.py <filename>')
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    filesize = int.from_bytes(data[4:8], byteorder='little')
    offset = int.from_bytes(data[8:12], byteorder='little')
    ins_size = int.from_bytes(data[12:16], byteorder='little')
    f = data[16:16+filesize]
    instructions = data[offset:offset+ins_size]
    decompile(instructions)

if __name__ == '__main__':
    main()