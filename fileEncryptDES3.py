from Crypto.Cipher import DES3
from Crypto.Hash import SHA256 as SHA
from os import path

SIZE = 1024

class fileDES():
    def __init__(self, keytext, ivtext):
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        self.key = key[:24]

        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv = iv[:8]

    def makeEncInfo(self, filename):
        fillersize = 0
        filesize = path.getsize(filename)
        if filesize % 8 != 0:
            fillersize = 8 - filesize % 8
        filler = '0' * fillersize
        header = str(fillersize)
        gap = 8 - len(header)
        header = header + '#' * gap
        return header, filler 

    def enc(self, filename):
        header, filler = self.makeEncInfo(filename)
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)
        encfilename = filename + '.enc'
        h = open(filename, 'rb')
        hh = open(encfilename, 'wb+')
        enc = header.encode('utf-8')
        content = h.read(SIZE)
        content = enc + content
        while content:
            if len(content) < SIZE:
                content += filler.encode('utf-8')
            enc = des3.encrypt(content)
            hh.write(enc)
            content = h.read(SIZE)
        h.close()
        hh.close()
        return encfilename

    def dec(self, encfilename):
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)
        h = open(encfilename + '.dec', 'wb+')
        hh = open(encfilename, 'rb')
        content = hh.read(8)
        dec = des3.decrypt(content)
        header = dec.decode()
        fillersize = int(header.split('#')[0])
        content = hh.read(SIZE)
        while content:
            dec = des3.decrypt(content)
            if len(dec) < SIZE:
                if fillersize != 0:
                    dec = dec[:-fillersize]
            h.write(dec)
            content = hh.read(SIZE)
        h.close()
        hh.close()

def main():
    filename = 'plain.txt'
    keytext = 'ninanung'
    ivtext = '1234'

    cipher = fileDES(keytext, ivtext)
    cipher.dec(cipher.enc(filename))

if __name__ == "__main__":
    main()