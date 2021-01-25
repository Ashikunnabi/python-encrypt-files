import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class FileReader:

    def __init__(self, file):
        self.file = file

    def read(self):
        with open(self.file, 'rb') as file:
            data = file.read()
        return data


class FileWriter:

    def __init__(self, file, data):
        self.file = file
        self.data = data

    def write(self):
        with open(self.file, 'wb') as file:
            file.write(self.data)
        return True


class Encryption:

    def __init__(self, file):
        self.file = file

    def encrypt(self):
        # generate key file
        if not os.path.exists('key.bin'):
            key = get_random_bytes(16)
            FileWriter('key.bin', key).write()
        else:
            key = FileReader('key.bin').read()

        cipher = AES.new(key, AES.MODE_EAX)

        file = FileReader(self.file).read()
        ciphertext, tag = cipher.encrypt_and_digest(file)

        with open(f"{self.file}.bin", "wb") as encrypted_file:
            [encrypted_file.write(x) for x in (cipher.nonce, tag, ciphertext)]

        # delete original file
        os.remove(self.file)


class Decryption:

    def __init__(self, file):
        self.file = file

    def decrypt(self):
        # read key file
        key = FileReader('key.bin').read()

        # read encrypted file
        with open(self.file, 'rb') as file:
            nonce, tag, ciphertext = [file.read(x) for x in (16, 16, -1)]

        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        file_name = self.file.replace('.bin', '')
        with open(file_name, 'wb') as real_file:
            real_file.write(data)

        # delete encrypted file
        os.remove(self.file)
        return True


class Cryptor:

    def encrypt_all_files(self):
        dirs = self.get_all_files()
        for file_name in dirs:
            Encryption(file_name).encrypt()

    def decrypt_all_files(self):
        dirs = self.get_all_files()
        for file_name in dirs:
            Decryption(file_name).decrypt()

    @staticmethod
    def get_all_files():
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dir_name, sub_dir_list, file_list in os.walk(dir_path):
            if 'venv' not in dir_name:
                for name in file_list:
                    if name not in ['cryptor.py', 'key.bin']:
                        dirs.append(dir_name + "/" + name)
        return dirs


if __name__ == '__main__':
    print('Select option:')
    print(' 1. Encrypt (All) \n 2. Decrypt (All) \n '
          '3. Encrypt (Single) \n 4. Decrypt (Single)')
    choice = input('What is your choice: ')

    if choice == '1':
        Cryptor().encrypt_all_files()
    elif choice == '2':
        Cryptor().decrypt_all_files()
    elif choice == '3':
        file = input('File name with extension: ')
        Encryption(file).encrypt()
    elif choice == '4':
        file = input('File name with extension: ')
        Decryption(file).decrypt()
    else:
        print('Wrong input')






