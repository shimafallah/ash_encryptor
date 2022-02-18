from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
import argparse
import hashlib
import re



class Encryptor:
	def __init__(self, key):
		self.key = key

	def encrypt(self, message, key):
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_GCM, iv)
		return iv + cipher.encrypt(message)

	def encrypt_file(self, file_name):
		with open(file_name, 'rb') as fo:
			plaintext = fo.read()
		file_encode = f'({file_name})'.encode()
		file_byte = file_encode + plaintext
		enc = self.encrypt(file_byte, self.key)
		f_name, f_ext = os.path.splitext(file_name)
		with open(f_name + ".ash", 'wb') as fo:
			fo.write(enc)
		os.remove(file_name)
		

	def decrypt(self, ciphertext, key):
		iv = ciphertext[:AES.block_size]
		cipher = AES.new(key, AES.MODE_GCM, iv)
		plaintext = cipher.decrypt(ciphertext[AES.block_size:])
		return plaintext.rstrip(b"\0")

	def decrypt_file(self, file_name):
		with open(file_name, 'rb') as fo:
			ciphertext = fo.read()
		dec = self.decrypt(ciphertext, self.key)
		string_file =str(dec)[2:-1]
		re_gex = re.compile('(?m)\(([^)]+)\)')
		regex_match = re_gex.match(string_file)
		regex_m = regex_match[1]
		dec_file = string_file.replace(f"({regex_m})", '')
		dec_file = bytes(dec_file, 'ascii')
		c = dec_file.decode('unicode-escape').encode('ISO-8859-1')
	
		with open(regex_m, 'wb') as fo:
			fo.write(c)
		os.remove(file_name)
	

try:
	parser = argparse.ArgumentParser(description="Encrypt and Decrypt")
	parser.add_argument('func', nargs='?', choices=['e','d'], default='e')
	args, sub_args = parser.parse_known_args()

	if args.func == 'e':
		try:
			parser = argparse.ArgumentParser(description='Encrypt')
			parser.add_argument('-f', nargs=1, help='your file name')
			parser.add_argument('-p',nargs=1, help='this is your password')
			args = parser.parse_args(sub_args)
			for i in args.p:
				password = i
			PasswordHash = hashlib.md5(password.encode()).hexdigest()
			CombinedKey = password + PasswordHash[:32 - len(password)]
			CombinedKey = CombinedKey.encode()
			enc = Encryptor(CombinedKey)
			if args.f:
				for i in args.f:
					enc.encrypt_file(i)
		except:
			print('You must use e -p your_password -f your_name_file')

	elif args.func == 'd':
		try:
			parser = argparse.ArgumentParser(description='Decrypt')
			parser.add_argument('-f', nargs=1, help='your file name')
			parser.add_argument('-p',nargs=1, help='this is your password')
			args = parser.parse_args(sub_args)
			for i in args.p:
				password = i
			PasswordHash = hashlib.md5(password.encode()).hexdigest()
			CombinedKey = password + PasswordHash[:32 - len(password)]
			CombinedKey = CombinedKey.encode()
			enc = Encryptor(CombinedKey)
			if args.f:
				for i in args.f:
					enc.decrypt_file(i)
		except:
			print('You must use d -p your_password(same the encrypt) -f your_name_file+ash')


	else:
		print('Error')
except:
	print('You must follow the instructions')



