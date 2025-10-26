import re
from sage.all import *
from tqdm import tqdm
results = []
for it in tqdm(range(10000)):
    with open('../dlls/%04d.dll' % it, 'rb') as f:
        data = f.read()

    res = re.findall(b'\x48\xb8(.{8})\xba\x00\x00\x00\x00', data, re.DOTALL)
    assert len(res) == 33

    modulo = int.from_bytes(res[0], 'little')
    exponent = int.from_bytes(re.findall(b'\x48\x89\x95\x48\x05\x00\x00\x48\xB8(.{8})\x48\x89\x85\x38\x05\x00\x00', data, re.DOTALL)[0], 'little')
    xor = [int.from_bytes(x, 'little') for x in res[1:17]]
    result = [int.from_bytes(x, 'little') for x in res[17:]]

    Fp = GF(modulo)
    resmat = Matrix(Fp, [[result[i * 4 + j] for j in range(4)] for i in range(4)])

    ordr = resmat.multiplicative_order()

    invexp = pow(exponent, -1, ordr)

    invres = resmat ** invexp
    assert invres ** exponent == resmat

    xorresult = [int(invres[i // 4][i % 4]) ^ xor[i] for i in range(16)]
    assert len(set(xorresult)) == 4

    results.append(xorresult[:4])

import json

with open('result1.txt', 'w') as f:
    f.write(json.dumps(results))