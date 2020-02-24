import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.serialization import load_pem_private_key  
from cryptography.hazmat.primitives.serialization import load_pem_public_key  

def newaccaunt():
	global login
	login = input("Create a login: ")
	login_hash = hashlib.md5(login.encode())
	login_file = open("test/" + login + "_hash.login", "w")
	login_file.write(login_hash.hexdigest())
	login_file.close()

	global password
	password = input("Creat a password: ")
	password_hash = hashlib.md5(password.encode())
	password_file = open("test/" + login + "password_hash.txt", "w")
	password_file.write(password_hash.hexdigest())
	password_file.close()

	print("Creating keys...")

	# Генерация RSA ключей
	private_key = rsa.generate_private_key(
	        public_exponent=65537,
	        key_size=2048,
	        backend=default_backend()
	    )

	public_key = private_key.public_key()

	# Сохранение приватного ключа в формате PEM  
	with open("test/privky_"+login+".pem", "wb") as f:  
	    f.write(private_key.private_bytes(  
	        encoding=serialization.Encoding.PEM,  
	        format=serialization.PrivateFormat.TraditionalOpenSSL,  
	        encryption_algorithm=serialization.BestAvailableEncryption(bytes(password, encoding='utf-8')),  
	    )  
	)
	f.close()  
	  
	# Сохранение публичного ключа в формате PEM 
	with open("test/pubeky_"+login+".pem", "wb") as f:  
	    f.write(public_key.public_bytes(  
	        encoding=serialization.Encoding.PEM,  
	        format=serialization.PublicFormat.SubjectPublicKeyInfo,  
	    )  
	)
	f.close()

def mess_en_dec():
	message = input("Put your message: ")
	reader = input("Who should to get a message\{put his login\}: ")

	print("Encrypting...")

	PubKey = load_pem_public_key(open('test/pubeky_'+reader+'.pem', 'rb').read(),default_backend())  

	encrtext = PubKey.encrypt(  
	    bytes(message, encoding='utf-8'),  
	    padding.OAEP(  
	            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
	            algorithm=hashes.SHA256(),  
	            label=None  
	  )  
	)

	print("Encrypted:\n" + str(encrtext))


	print("\nDecrypting...")

	PrivKey = load_pem_private_key(open('test/privky_' + login + '.pem', 'rb').read(),bytes(password, encoding='utf-8'),default_backend())  

	d = PrivKey.decrypt(  
	    encrtext,  
	    padding.OAEP(  
	            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
	            algorithm=hashes.SHA256(),  
	            label=None  
	  )  
	)  

	print("Decripted:")
	print(d)

def exiting():
	print("exiting...")
	listdir = os.listdir("test")
	for files in listdir:
		os.remove("test/"+files)
		print(f"file: {files} deleted")
	exit()

while True:
	print("[1]Create accaunt")
	print("[2]Exit")
	answ = input("What do you want? ")
	if answ == "1":
		newaccaunt()
		if input("Creat a message? [y/N]") == "y":
			mess_en_dec()
		else:
			exiting()
	elif answ == "2":
		exiting()
	else:
		print("No such variant")
