import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from stegano import lsb


def keyCreation(key):
    block_size = 32
    # Getting a hash value of 256 bit (32 byte)
    key = hashlib.sha256(key.encode()).digest()
    return key


def hide(input_filename, output_filename, data, key):

    block_size = 32
    # Get a random initialization vector
    iv = Random.new().read(AES.block_size)
    # using Cipher Block Chaining (CBC) Mode
    encryption_suite = AES.new(key, AES.MODE_CBC, iv)

    # If it is string convert to byte string before use it
    if isinstance(data, str):
        data = data.encode()

    # Encrypt the random initialize vector added with the padded data
    cipher_data = encryption_suite.encrypt(iv + pad(data, block_size))

    # Convert the cipher byte string to a base64 string to avoid decode padding error
    cipher_data = base64.b64encode(cipher_data).decode()
    print("Cipher text is :", cipher_data)

    # Hide the encrypted data in the image via LSB technique.
    secret = lsb.hide(input_filename, cipher_data)
    secret.save(output_filename)


def retrieve(input_image_file, key):

    block_size = 32
    cipher_data = lsb.reveal(input_image_file)

    if not cipher_data:
        return None

    cipher_data = base64.b64decode(cipher_data)
    # Retrieve the dynamic initialization vector saved
    iv = cipher_data[:AES.block_size]
    # Retrieved the cipher data
    cipher_data = cipher_data[AES.block_size:]

    try:
        decryption_suite = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(
            decryption_suite.decrypt(cipher_data),
            block_size
        )
        try:
            return decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            # Binary data - returns as it is
            return decrypted_data
    except ValueError:
        return None


if __name__ == '__main__':
    option = int(input(":: Welcome to Steganography ::\n"
                       "1. Encode\n 2. Decode\n"))

    if option == 1:
        data = input("Enter Data : ")
        password = input("Enter Key : ")
        hkey = keyCreation(password)

        absolute_path_original_image = input("Enter absolute Path with file name & extension : ")
        absolute_path_new_image = input("Enter absolute Path with file name & extension for new image : ")
        hide(absolute_path_original_image, absolute_path_new_image, data, hkey)

    if option == 2:
        new_image = input("Enter absolute Path with file name & extension :")
        password = input("Enter Key : ")
        hkey = keyCreation(password)
        data = retrieve(new_image, hkey)
        print("data recovered is :", data)