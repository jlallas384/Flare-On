def decrypt(data, key):
    s = [i for i in range(256)]
    ret = ['_'] * len(data)

    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    
    i, j = 0, 0
    for _ in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        ret[_] = data[_] ^ s[t]

    return bytes(ret)