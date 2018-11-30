from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as SHA

class myAES():
    def __init__(self, keytext, ivtext):
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        self.key = key[:16]

        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv = iv[:16]

    def makeEnabled(self, plaintext):
        fillersize = 0
        textsize = len(plaintext)
        if textsize % 16 != 0:
            fillersize = 16 - textsize % 16
        filler = '0' * fillersize
        header = str(fillersize)
        header += '#' * (16 - len(header))
        return header + plaintext + filler

    def enc(self, plaintext):
        plaintext = self.makeEnabled(plaintext)
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        encmsg = aes.encrypt(plaintext.encode())
        return encmsg

    def dec(self, ciphertext):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        decmsg = aes.decrypt(ciphertext)

        header = decmsg[:16].decode()
        fillersize = int(header.split('#')[0])
        if fillersize != 0:
            decmsg = decmsg[16:-fillersize]
        else:
            decmsg = decmsg[16:]
        return decmsg

def main():
    keytext = 'samsjang'
    ivtext = '1234'
    msg = 'python35ab'

    cipher = myAES(keytext, ivtext)
    ciphered = cipher.enc(msg)
    deciphered = cipher.dec(ciphered)
    print(msg)
    print(ciphered)
    print(deciphered)

if __name__ == '__main__':
    main()