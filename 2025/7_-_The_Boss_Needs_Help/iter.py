from scapy.all import rdpcap, TCP, Raw
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PCAP_FILE = "packets.pcapng"


packets = rdpcap(PCAP_FILE)
import json

p1 = b'TheBoss@THUNDERNODE'
p2 = b'peanut06'

def compute(p1, p2):
    from hashlib import sha256
    bx1 = sha256(p1).digest()
    bx2 = sha256(p2).digest()
    return bytes([x ^ y for x, y in zip(bx1, bx2)])

key = compute(p1, p2)

iv = bytes.fromhex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
for i, pkt in enumerate(packets):

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode(errors='ignore')

            if "\"d\"" in payload:
                ciph = AES.new(key, AES.MODE_CBC, iv=iv)
                x = json.loads(payload)['d']
                x = bytes.fromhex(x)
                try:
                    l = unpad(ciph.decrypt(x),16).decode()
                    print(l)
                    l = json.loads(l)
                    if l['msg'] == 'cmd':
                        dd = l['d']
                        if dd['cid'] == 6:
                            key = compute(p1, dd['np'].encode() + b'06')
                            print(key)
                except:
                    pass
        except UnicodeDecodeError:
            continue
        except json.decoder.JSONDecodeError:
            continue
