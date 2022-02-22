import argparse
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import os
import re



class Ash:
	def __init__(self, key):
		self.key = key

	def encrypt(self, message, key):
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_GCM, iv)
		return iv + cipher.encrypt(message)

	def encrypt_file(self, file_name):
		if os.path.isfile(file_name):
			with open(file_name, 'rb') as fo:
				plaintext = fo.read()
		else:
			print ("File doesn't exists")
		file_encode = f'({file_name})'.encode() #Get filename
		file_byte = file_encode + plaintext #Add filename to bytes
		enc = self.encrypt(file_byte, self.key)
		f_name, f_ext = os.path.splitext(file_name) #Get file name without extension
		if f_ext == '.ash':
			print("You can't encrypt ash file!")
		else:
			with open(f_name + ".ash", 'wb') as fo:
				fo.write(enc)
				print(f"File Encrypted as {f_name}.ash")
			os.remove(file_name)
			

	def decrypt(self, ciphertext, key):
		iv = ciphertext[:AES.block_size]
		cipher = AES.new(key, AES.MODE_GCM, iv)
		plaintext = cipher.decrypt(ciphertext[AES.block_size:])
		return plaintext.rstrip(b"\0")

	def decrypt_file(self, file_name):
		if os.path.isfile(file_name):
			with open(file_name, 'rb') as fo:
				ciphertext = fo.read()
		else:
			print ("File doesn't exists")
		dec = self.decrypt(ciphertext, self.key)
		string_file =str(dec)[2:-1]
		re_gex = re.compile('(?m)\(([^)]+)\)')
		regex_match = re_gex.match(string_file) 
		regex_m = regex_match[1] #Get filename
		dec_file = string_file.replace(f"({regex_m})", '')
		dec_file = bytes(dec_file, 'utf-8')
		c = dec_file.decode('unicode-escape').encode('ISO-8859-1') #Remove double slash 
		with open(regex_m, 'wb') as fo:
			fo.write(c)
			print('File Decrypted Successfully')
		os.remove(file_name)


def args_file():
	class ArgumentParserError(Exception): pass
	class ThrowingArgumentParser(argparse.ArgumentParser):
		def error(self, message):
			raise ArgumentParserError(message)

	parser = ThrowingArgumentParser(description="Encrypt and Decrypt")
	parser.add_argument('func', nargs='?', choices=['e','d'], const='')
	
	try:
		args, sub_args = parser.parse_known_args()
	except:
		print('You Have to use one of e or d to encrypt or decrypt')
	
	parser.add_argument('-f', nargs=1, help='Your filename')
	parser.add_argument('-p',nargs=1 ,help='Your password')
	try:
		arg_parse = parser.parse_args(sub_args)
		#For password
		if arg_parse.p is not None:
			for i in arg_parse.p:
				password = i
			PasswordHash = hashlib.md5(password.encode()).hexdigest()
			CombinedKey = password + PasswordHash[:32 - len(password)]
			CombinedKey = CombinedKey.encode()
			enc = Ash(CombinedKey)
			
		else:
			print('Please Use -p to enter Password')
	except:
		print("Password and Filename Can't Be Empty")
	
	
	# return arg_parse, enc, args

	try:
		# args= args_file()[2]
		if args.func == 'e':
			try:
				# arg_parse = args_file()[0]
				# enc = args_file()[1]
				if arg_parse.f is not None:
					for i in arg_parse.f:
						enc.encrypt_file(i)
				else:
					print('Please Use -f to enter filename')
			except ValueError:
				print('Password cannot be more than 32 letter')

		elif args.func == 'd':
			try:
				# args = args_file()[0]
				# enc = args_file()[1]
				if arg_parse.f is not None:
					for i in arg_parse.f:
						enc.decrypt_file(i)
				else:
					print('Please Use -f to enter filename')
			except TypeError:
				print('Your password is not the same')
		else:
			print('You Have to use one of e or d to encrypt or decrypt')
	except NameError:
		pass

def main():
    args_file()

