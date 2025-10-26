import json
import pickle
import os
import tqdm

def load_json(name):
    pname = name + 'cache'
    if (os.path.exists(pname)):
        with open(pname, "rb") as f:
            return pickle.load(f)
    j = json.loads(open(name, 'r').read())
    with open(pname, 'wb') as f:
        pickle.dump(j, f, protocol=pickle.HIGHEST_PROTOCOL)
    return j

ops = load_json("ops.txt")
funcs = load_json("funcs.txt")
nums = load_json("result1.txt")
fn_nums = load_json("fn_nums.txt")
imports = load_json("imports.txt")

phi_2n = 2**255

ff = b''

sums = [0] * 10000
tt = 0
for it in tqdm.tqdm(fn_nums):
    ff += it.to_bytes(2, 'little')
    a = []
    for x in nums[it]:
        a += [int(y) for y in x.to_bytes(8, 'little')]
    fail = 0
    assert len(ops[it]) > 500
    for dll, fname in reversed(ops[it]):

        func = funcs[dll][fname]
        vals = bytes.fromhex(func['ops'])
        if func['kind'] == 0:
            assert len(vals) == 256
            invsbox = [0] * 256
            for i in range(256):
                invsbox[vals[i]] = i
            for i in range(32):
                a[i] = invsbox[a[i]]

        elif func['kind'] == 1:
            inv = [0] * 32
            for i in range(32):
                inv[vals[i]] = i
            b = a[:]
            for i in range(32):
                a[i] = b[inv[i]]
        else:
            num = int.from_bytes(bytes(a), 'little')
            og = num & 1
            assert len(vals) == 31

            exp = int.from_bytes(vals, 'little')
            num |= 1



            dexp = pow(exp, -1, phi_2n)
            num = pow(num, dexp, 2 ** 256)

            #print(num, dexp)
            num = (num & ~0x1) | og
            #print('here')

            a = [int(x) for x in num.to_bytes(32, 'little')]

        xorer = sums[dll]
        for i in range(4):
            a[i] ^= (xorer >> (8 * i)) & 0xff
            #print(a)
        #print(fname, a)
    for u in imports[it]:
        sums[u] += tt

    tt += 1
    ff += bytes(a)

with open('license.bin', 'wb') as f:
    f.write(ff)