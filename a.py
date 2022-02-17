from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
import argparse
import hashlib
import re


class Encryptor:
	def __init__(self, key, nonce):
		self.key = key
		self.nonce = nonce

	def encrypt(self, message, key):
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_GCM, iv)
		self.nonce = cipher.nonce
		return iv + cipher.encrypt(message)

	def encrypt_file(self, file_name):
		with open(file_name, 'rb') as fo:
			plaintext = fo.read()
			file_byte = f'({file_name})'.encode('utf-8') + plaintext
		enc = self.encrypt(file_byte, self.key)
		f_name, f_ext = os.path.splitext(file_name)
		with open(f_name + ".ash", 'wb') as fo:
			fo.write(enc)
		os.remove(file_name)
		# return f_name

	def decrypt(self, ciphertext, key):
		iv = ciphertext[:AES.block_size]
		cipher = AES.new(key, AES.MODE_GCM, iv, nonce=self.nonce)
		
		plaintext = cipher.decrypt(ciphertext[AES.block_size:])
		
		return plaintext.rstrip(b"\0")

	def decrypt_file(self, file_name):
		
		with open(file_name, 'rb') as fo:
			ciphertext = fo.read()
		dec = self.decrypt(ciphertext, self.key)
		
		dec = dec.decode('utf-8')
	
		re_gex = re.compile('(?m)\(([^)]+)\)')

		regex_match = re_gex.match(dec)[1]
		dec_file = dec.replace(f"({regex_match})", '')
		dec_file = bytes(dec_file)
		

		with open(regex_match, 'wb') as fo:
			fo.write(dec_file)
		os.remove(file_name)


parser = argparse.ArgumentParser(description="Encrypt and Decrypt")
parser.add_argument('func', nargs='?', choices=['e','d'], default='e')
args, sub_args = parser.parse_known_args()

if args.func == 'e':
	parser = argparse.ArgumentParser(description='Encrypt')
	parser.add_argument('-f', nargs=1, help='your file name')
	parser.add_argument('-p',nargs=1, help='this is your password')
	args = parser.parse_args(sub_args)
	for i in args.p:
		password = i
	PasswordHash = hashlib.md5(password.encode('utf-8')).hexdigest()
	CombinedKey = password + PasswordHash[:32 - len(password)]
	CombinedKey = CombinedKey.encode('utf-8')
	nonce = b'\xfc\xbe\tA\xed\xe4W]\x04O\xc2\xe4\xd3\x83\x9d\x91'
	enc = Encryptor(CombinedKey, nonce=nonce)
	if args.f:
		for i in args.f:
			x = enc.encrypt_file(i)

elif args.func == 'd':
	parser = argparse.ArgumentParser(description='Decrypt')
	parser.add_argument('-f', nargs=1, help='your file name')
	parser.add_argument('-p',nargs=1, help='this is your password')
	args = parser.parse_args(sub_args)
	for i in args.p:
		password = i
	PasswordHash = hashlib.md5(password.encode('utf-8')).hexdigest()
	CombinedKey = password + PasswordHash[:32 - len(password)]
	CombinedKey = CombinedKey.encode('utf-8')
	nonce = b'\xfc\xbe\tA\xed\xe4W]\x04O\xc2\xe4\xd3\x83\x9d\x91'
	enc = Encryptor(CombinedKey, nonce)
	if args.f:
		for i in args.f:
			x = enc.decrypt_file(i)
	



