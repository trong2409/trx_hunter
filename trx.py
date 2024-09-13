import base58
import ecdsa
import requests
from Crypto.Hash import keccak
from rich import print
import random
import time

def keccak256(data):
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()

def get_signing_key(raw_priv):
    return ecdsa.SigningKey.from_string(raw_priv, curve=ecdsa.SECP256k1)

def verifying_key_to_addr(key):
    pub_key = key.to_string()
    primitive_addr = b'\x41' + keccak256(pub_key)[-20:]
    addr = base58.b58encode_check(primitive_addr)
    return addr

def check_balance(addr):
    try:
        response = requests.get(f"https://apilist.tronscan.org/api/account?address={addr}")
        response.raise_for_status()  # Raise error if status code is not 200
        res = response.json()

        if 'balances' in res and len(res['balances']) > 0:
            return float(res['balances'][0]['amount'])
        else:
            return 0.0
    except requests.RequestException as e:
        print(f"[red]Error fetching balance for {addr}: {str(e)}")
        return 0.0
    except (KeyError, ValueError):
        return 0.0

z = 0
w = 0

while True:
    raw = bytes(random.sample(range(0, 256), 32))
    key = get_signing_key(raw)
    addr = verifying_key_to_addr(key.get_verifying_key()).decode()
    priv = raw.hex()

    bal = check_balance(addr)

    print(f'[red1]Total Scan : [/][b blue]{z}[/]')
    print(f'[gold1]Address:     [/]{addr}           Balance: {bal}')
    print(f'[gold1]Address(hex):[/]{base58.b58decode_check(addr.encode()).hex()}')
    print(f'Public Key:  {key.get_verifying_key().to_string().hex()}')
    print(f'[gold1]Private Key: [/][red1]{priv}[/]\n')

    if bal > 0:
        w += 1
        with open("FileTRXWinner.txt", "a") as f:
            f.write(f'\nADDRESS: {addr}   BAL: {bal}')
            f.write(f'\nPRIVATEKEY: {priv}')
            f.write('\n------------------------')
    else:
        z += 1

    # Sleep to avoid hitting the API too frequently
    time.sleep(0.5)
