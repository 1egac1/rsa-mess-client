import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.serialization import load_pem_private_key  
from cryptography.hazmat.primitives.serialization import load_pem_public_key  

alredy_ex = []

	# Создание аккаунта
def creating_acc():
	# Создание логина и его сохранение
	global login 
	login = input("Create a login: ")
	os.mkdir(login + "_dir")
	os.mkdir(login + "_dir/keys")
	os.mkdir(login + "_dir/topics")
	loginfile = open(login + "_dir/login.hash", "w")
	hash_login = hashlib.md5(login.encode())
	loginfile.write(hash_login.hexdigest())
	loginfile.close()

	#  Создание и сохранение пароля
	passw = input("Create a password: ")
	passfile = open(login+"_dir/password.hash", "w")
	hash_object = hashlib.md5(passw.encode())
	passfile.write(hash_object.hexdigest())
	passfile.close()
	print("Creating keys...")

	# Генерация RSA ключей
	private_key = rsa.generate_private_key(
	        public_exponent=65537,
	        key_size=2048,
	        backend=default_backend()
	    )

	public_key = private_key.public_key()

	# Сохранение приватного ключа в формате PEM  
	with open(login + "_dir/keys/privky.pem", "wb") as f:  
	    f.write(private_key.private_bytes(  
	        encoding=serialization.Encoding.PEM,  
	        format=serialization.PrivateFormat.TraditionalOpenSSL,  
	        encryption_algorithm=serialization.BestAvailableEncryption(bytes(passw, encoding='utf-8')),  
	    )  
	)
	f.close()  
	  
	# Сохранение публичного ключа в формате PEM 
	with open(login + "_dir/keys/pubeky.pem", "wb") as f:  
	    f.write(public_key.public_bytes(  
	        encoding=serialization.Encoding.PEM,  
	        format=serialization.PublicFormat.SubjectPublicKeyInfo,  
	    )  
	)
	f.close()


	# Написание и зашифровка сообщений
def creating_message():
	# Написание сообщения и выбор получателя
	message = input("Put your message: ")
	reader = input("Who should to get a message{put his login}: ")
	print("Encrypting...")

	# Открытие публичного шифрования для шифрования
	PubKey = load_pem_public_key(open(reader+'_dir/keys/pubeky.pem', 'rb').read(),default_backend())  

	# Само шифрование
	encrtext = PubKey.encrypt(  
	    bytes(message, encoding='utf-8'),  
	    padding.OAEP(  
	            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
	            algorithm=hashes.SHA256(),  
	            label=None  
	  )  
	)
	# Проверка кол-ва "статей"
	check_files()
	numb = len(alredy_ex) + 1
	name = "topic_"+str(numb)
	# Запись
	f = open(reader+"_dir/topics/"+name, "wb")
	f.write(encrtext)
	auted()


	#РАСШИФРОВКА
def decrypting():
	to_open = login + "_dir/keys/privky.pem"
	encryptedpass = input("Put your password: ")
	print("Decrypting...")
	PrivKey = load_pem_private_key(open(to_open, 'rb').read(),bytes(encryptedpass, encoding='utf-8'),default_backend())  
	dirlist = os.listdir(path=login+"_dir/topics")
	for i in range(1, len(dirlist) + 1):
		print(str(i) + ". " + dirlist[i - 1])
	chose = int(input("Which file do you want to open[numb]"))
	chose -= 1
	topen = dirlist[chose]
	opend = open(login + "_dir/topics/" + topen, "rb")
	ciphertext = opend.read()
	d = PrivKey.decrypt(  
	    ciphertext,  
	    padding.OAEP(  
	            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
	            algorithm=hashes.SHA256(),  
	            label=None  
	  )  
	)  
	print("-"*50+"\n")
	print(d)
	print("\n"+"-"*50+"\n")
	auted()

def check_files():
	dirlist = os.listdir(path=login+"_dir/topics")
	intd = len(dirlist)
	for word in dirlist:
		for i in range(0, intd):
			if word == "topic" + str(i) + ".txt":
				alredy_ex.append("topic" + str(i) + ".txt")
				continue

def aut_ed():
	print("="*50)
	print("[1]Create message")
	print("[2]Decrypt message")
	print("[99]Exit")
	inptd = input("What are you want to do?{put a number}: ")
	if inptd == "1":
		creating_message()
	elif inptd == "2":
		decrypting()
	elif inptd == "99":
		exit()
	else:
		print("There are no such numb")

def autant():
	global login
	login = input("Put your login: ")
	loginfile = open(login+"_dir/login.hash", "r")
	inp_log_hash = hashlib.md5(login.encode())
	if inp_log_hash.hexdigest() == loginfile.read():
		inp_pass = input("Put your password: ")
		passfile = open(login+"_dir/password.hash", "r")
		inp_pass_hash = hashlib.md5(inp_pass.encode())
		if inp_pass_hash.hexdigest() == passfile.read():
			aut_ed()
		else:
			print("PASS NOT RIGHT")
	else:
		print("No such user")


while True:
	print("[1]If you have a accaunt")
	print("[2]If you havn't accaunt")
	print("[99]To exit")
	numbtouse = input("Put a numb: ")
	if numbtouse == "1":
		autant()
	elif numbtouse == "2":
		creating_acc()
	elif numbtouse == "99":
		exit()
	else:
		"No such numb"