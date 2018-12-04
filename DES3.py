from Crypto.Cipher import DES3
from Crypto.Hash import SHA256 as SHA

class myDES3():
    def __init__(self, textkey, textvec):
        hash = SHA.new()
        hash.update(textkey.encode('utf-8'))
        key = hash.digest()
        self.key = key[:24]

        hash.update(textvec.encode('utf-8'))
        vec = hash.digest()
        self.vec = vec[:8]

    def enc(self, plaintext):
        plaintext = self.make8string(plaintext)
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.vec)
        encmsg = des3.encrypt(plaintext.encode())
        return encmsg

    def dec(self, ciphertext):
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.vec)
        decmsg = des3.decrypt(ciphertext)
        return decmsg

    def make8string(self, text):
        remain = len(text) % 8
        if remain != 0:
            xs = 'x'*(8 - remain)
            text += xs
        return text

def main():
    textkey = 'samsjang'
    textvec = '1234'
    msg = 'python35ab'

    cipher = myDES3(textkey, textvec)
    ciphered = cipher.enc(msg)
    deciphered = cipher.dec(ciphered)
    print(msg)
    print(ciphered)
    print(deciphered)

if __name__ == '__main__':
    main()