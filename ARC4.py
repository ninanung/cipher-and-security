from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256 as SHA

class myARC4():
    def __init__(self, keytext):
        self.key = keytext

    def enc(self, plaintext):
        arc4 = ARC4.new(self.key)
        encmsg = arc4.encrypt(plaintext.encode())
        return encmsg

    def dec(self, ciphertext):
        arc4 = ARC4.new(self.key)
        decmsg = arc4.decrypt(ciphertext)
        return decmsg

def main():
    keytext = 'ninanung'
    msg = 'somepassword'
    cipher = myARC4(keytext)
    ciphered = cipher.enc(msg)
    deciphered = cipher.dec(ciphered)
    print(msg)
    print(ciphered)
    print(deciphered)

if __name__ == "__main__":
    main()