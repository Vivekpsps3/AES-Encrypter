#wraps AES.py
from AES import AES


#keyfile = input("Enter the name of the file containing the key: ")
keyfile = "iloveencryptionsiloveencryptions"
cipher = AES(key=keyfile)

cipher.encrypt("input.txt", "encrypted.txt")

