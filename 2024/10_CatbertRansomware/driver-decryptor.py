import rc4

def main():
    file_name = 'DilbootApp.efi.enc'
    with open(file_name, 'rb') as f:
        data = f.read()

    key1 = b"DaCubicleLife101"
    key2 = b"G3tDaJ0bD0neM4te"
    key3 = b"VerYDumBpassword"

    fkey = ['_'] * 16
    fkey[0] = key3[7]
    fkey[1] = key3[5]
    fkey[2] = key3[2]
    fkey[3] = key3[1]
    fkey[4] = key1[1]
    fkey[5] = key3[5]
    fkey[6] = key1[6]
    fkey[7] = key3[2]
    fkey[8] = key1[1]
    fkey[9] = key1[6]
    fkey[10] = key3[3]
    fkey[11] = key1[13] + 3
    fkey[12] = key1[9]
    fkey[13] = key1[10]
    fkey[14] = key1[11]
    fkey[15] = key1[12]

    with open(file_name[:-4], 'wb') as f:
        f.write(rc4.decrypt(data, fkey))
if __name__ == '__main__':
    main()

    