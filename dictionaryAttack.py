import crypt

def findPass(passhash, dictfile):
    array = passhash.split('$')
    salt = ''
    password = ''
    if array[1] == '1':
        salt = passhash[3:5]
        password = passhash[3:]
    elif array[1] == '6':
        salt = '$6$' + array[2]
        password = '$' + array[3]
    with open(dictfile, 'r') as file:
        for word in file.readlines():
            word = word.split('\n')[0]
            cryptword = crypt.crypt(word, salt)
            fullword = salt + password
            if fullword == cryptword:
                return word
    return ''

def readFile(filename):
    file = open(filename, 'rt')
    text = file.read()
    return text

def main():
    print(findPass(readFile('SHA512.txt'), 'dictfile.txt'))

if __name__ == "__main__":
    main()