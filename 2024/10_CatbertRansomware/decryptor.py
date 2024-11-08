import sys
import rc4

def parse(data):
    filesize = int.from_bytes(data[4:8], byteorder='little')
    f = data[16:16+filesize]
    return f

def main():
    if len(sys.argv) != 3:
        print('Usage: python decryptor.py <filename> <key>')
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    data = parse(data)
    key = sys.argv[2].encode()

    with open(sys.argv[1][:-5], 'wb') as f:
        f.write(rc4.decrypt(data, key))

if __name__ == '__main__':
    main()