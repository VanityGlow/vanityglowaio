import requests,os
from time import sleep
from colorama import Fore
import random
import json as jsond  # json
import time  # sleep before exit
import binascii  # hex encoding
import requests  # https requests
from uuid import uuid4  # gen random guid
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
# aes + padding, sha256
import webbrowser
import platform
import subprocess
import datetime
import sys
import os
import os.path
from datetime import datetime
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter

if os.name == 'nt':
	os.system("cls")
else:
	os.system("clear")

tokens = open("tokens.txt", 'r').read().splitlines()

def sentance():
	sentance = open("sentences.txt", encoding="cp437", errors='ignore').read().splitlines()
	return random.choice(sentance)

def proxies():
	proxies = open("proxies.txt").read().splitlines()
	return random.choice(proxies)

headers = {
	"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjkzLjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvOTMuMCIsImJyb3dzZXJfdmVyc2lvbiI6IjkzLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTAwODA0LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
	"sec-fetch-dest": "empty",
	"x-debug-options": "bugReporterEnabled",
	"sec-fetch-mode": "cors",
	"sec-fetch-site": "same-origin",
	"accept": "*/*",
	"accept-language": "en-GB",
	"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.16 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
	"TE": "trailers"
}

headers_reg = {
    "accept": "*/*",
    "authority": "discord.com",
    "method": "POST",
    "path": "/api/v9/auth/register",
    "scheme": "https",
    "origin": "discord.com",
    "referer": "discord.com/register",
    "x-debug-options": "bugReporterEnabled",
    "accept-language": "en-US,en;q=0.9",
    "connection": "keep-alive",
    "content-Type": "application/json",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
    "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjIwMDAiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTA0OTY3LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin"
}

payload = {
	'tts': 'false'
}
payload2 = {
	'tts': 'false'
}

######################################################################################################################################################################################################################################################################
def login():
	class api:
		name = ownerid = secret = version = ""

		def __init__(self, name, ownerid, secret, version):
			self.name = name

			self.ownerid = ownerid

			self.secret = secret

			self.version = version

		sessionid = enckey = ""

		def init(self):

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("init").encode()),
				"ver": encryption.encrypt(self.version, self.secret, init_iv),
				"enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)

			if response == "KeyAuth_Invalid":
				print("The application doesn't exist")
				sys.exit()

			response = encryption.decrypt(response, self.secret, init_iv)
			json = jsond.loads(response)

			if not json["success"]:
				print(json["message"])
				sys.exit()

			self.sessionid = json["sessionid"]

		def register(self, user, password, license, hwid=None):
			if hwid is None:
				hwid = others.get_hwid()

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("register").encode()),
				"username": encryption.encrypt(user, self.enckey, init_iv),
				"pass": encryption.encrypt(password, self.enckey, init_iv),
				"key": encryption.encrypt(license, self.enckey, init_iv),
				"hwid": encryption.encrypt(hwid, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)

			response = encryption.decrypt(response, self.enckey, init_iv)

			json = jsond.loads(response)

			if json["success"]:
				print("successfully registered")
			else:
				print(json["message"])
				sys.exit()

		def upgrade(self, user, license):

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("upgrade").encode()),
				"username": encryption.encrypt(user, self.enckey, init_iv),
				"key": encryption.encrypt(license, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)

			response = encryption.decrypt(response, self.enckey, init_iv)

			json = jsond.loads(response)

			if json["success"]:
				print("successfully upgraded user")
			else:
				print(json["message"])
				sys.exit()

		def login(self, user, password, hwid=None):
			if hwid is None:
				hwid = others.get_hwid()

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("login").encode()),
				"username": encryption.encrypt(user, self.enckey, init_iv),
				"pass": encryption.encrypt(password, self.enckey, init_iv),
				"hwid": encryption.encrypt(hwid, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)

			response = encryption.decrypt(response, self.enckey, init_iv)

			json = jsond.loads(response)

			if json["success"]:
				self.__load_user_data(json["info"])
				print("successfully logged in")
			else:
				print(json["message"])
				sys.exit()

		def license(self, key, hwid=None):
			if hwid is None:
				hwid = others.get_hwid()

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("license").encode()),
				"key": encryption.encrypt(key, self.enckey, init_iv),
				"hwid": encryption.encrypt(hwid, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)
			response = encryption.decrypt(response, self.enckey, init_iv)

			json = jsond.loads(response)

			if json["success"]:
				self.__load_user_data(json["info"])
				print("successfully logged into license")
			else:
				print(json["message"])
				sys.exit()

		def var(self, name):

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("var").encode()),
				"varid": encryption.encrypt(name, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)

			response = encryption.decrypt(response, self.enckey, init_iv)

			json = jsond.loads(response)

			if json["success"]:
				return json["message"]
			else:
				print(json["message"])
				time.sleep(5)
				sys.exit()

		def file(self, fileid):

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("file").encode()),
				"fileid": encryption.encrypt(fileid, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)

			response = encryption.decrypt(response, self.enckey, init_iv)

			json = jsond.loads(response)

			if not json["success"]:
				print(json["message"])
				time.sleep(5)
				sys.exit()
			return binascii.unhexlify(json["contents"])

		def webhook(self, webid, param):

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("webhook").encode()),
				"webid": encryption.encrypt(webid, self.enckey, init_iv),
				"params": encryption.encrypt(param, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			response = self.__do_request(post_data)

			response = encryption.decrypt(response, self.enckey, init_iv)
			json = jsond.loads(response)

			if json["success"]:
				return json["message"]
			else:
				print(json["message"])
				time.sleep(5)
				sys.exit()

		def log(self, message):

			init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

			post_data = {
				"type": binascii.hexlify(("log").encode()),
				"pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
				"message": encryption.encrypt(message, self.enckey, init_iv),
				"sessionid": binascii.hexlify(self.sessionid.encode()),
				"name": binascii.hexlify(self.name.encode()),
				"ownerid": binascii.hexlify(self.ownerid.encode()),
				"init_iv": init_iv
			}

			self.__do_request(post_data)

		def __do_request(self, post_data):

			rq_out = requests.post(
				"https://keyauth.win/api/1.0/", data=post_data
			)

			return rq_out.text

		# region user_data
		class user_data_class:
			username = ip = hwid = expires = createdate = lastlogin = ""

		user_data = user_data_class()

		def __load_user_data(self, data):
			self.user_data.username = data["username"]
			self.user_data.ip = data["ip"]
			self.user_data.hwid = data["hwid"]
			self.user_data.expires = data["subscriptions"][0]["expiry"]
			self.user_data.createdate = data["createdate"]
			self.user_data.lastlogin = data["lastlogin"]


	class others:
		@staticmethod
		def get_hwid():
			if platform.system() != "Windows":
				return "None"

			cmd = subprocess.Popen(
				"wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)

			(suppost_sid, error) = cmd.communicate()

			suppost_sid = suppost_sid.split(b'\n')[1].strip()

			return suppost_sid.decode()


	class encryption:
		@staticmethod
		def encrypt_string(plain_text, key, iv):
			plain_text = pad(plain_text, 16)

			aes_instance = AES.new(key, AES.MODE_CBC, iv)

			raw_out = aes_instance.encrypt(plain_text)

			return binascii.hexlify(raw_out)

		@staticmethod
		def decrypt_string(cipher_text, key, iv):
			cipher_text = binascii.unhexlify(cipher_text)

			aes_instance = AES.new(key, AES.MODE_CBC, iv)

			cipher_text = aes_instance.decrypt(cipher_text)

			return unpad(cipher_text, 16)

		@staticmethod
		def encrypt(message, enc_key, iv):
			try:
				_key = SHA256.new(enc_key.encode()).hexdigest()[:32]

				_iv = SHA256.new(iv.encode()).hexdigest()[:16]

				return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
			except:
				print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
				sys.exit()

		@staticmethod
		def decrypt(message, enc_key, iv):
			try:
				_key = SHA256.new(enc_key.encode()).hexdigest()[:32]

				_iv = SHA256.new(iv.encode()).hexdigest()[:16]

				return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
			except:
				print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
				sys.exit()


	# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA

	keyauthapp = api("Vanity Glow AIO", "PFXjTWefvj", "c80894d092da738907df9c22a01631633edef06393ed277333e69fe38e330d8b","1.0")

	print(f"{Fore.YELLOW}Initializing")
	keyauthapp.init()
	key = input(f'{Fore.RED}Enter your license: ')
	keyauthapp.license(key)

	print(f"\n{Fore.GREEN}User data: ") 
	print(f"Username: " + keyauthapp.user_data.username)
	print(f"IP address: " + keyauthapp.user_data.ip)
	print(f"Hardware-Id: " + keyauthapp.user_data.hwid)


def request_cookie():
	response1 = requests.get("https://discord.com")
	cookie = response1.cookies.get_dict()
	cookie['locale'] = "us"
	return cookie

def request_fingerprint():
	response2 = requests.get("https://discordapp.com/api/v9/experiments", headers=headers_reg).json()
	fingerprint = response2["fingerprint"]
	return fingerprint

def nibv():
	proxies = open('proxies.txt','r').read().splitlines()
	proxies = [{'https':'http://'+proxy} for proxy in proxies]
	joincount = 0
	reactioncount = 0
	invite_code = input(f"\n{Fore.RED} Discord Invite Code (not link): {Fore.RESET}")
	channelid = input(f"{Fore.RED} Channel ID (Verification): {Fore.RESET}")
	messageid = input(f"{Fore.RED} Message ID (Verification): {Fore.RESET}")
	emojihash = input(f"{Fore.RED} Emoji Hash (Check ReadME.txt): ")
	timeout = int(input(f"{Fore.RED} Timeout (5-10): {Fore.RESET}"))

	if (invite_code == "" or timeout == ""):
		print(f"{Fore.GREEN} Your provided an invalid invite code or timeout!{Fore.RESET}")
		os._exit(1)

	for x in range(len(tokens)):
		try:
			headers["authorization"] = tokens[x]
			headers["x-fingerprint"] = request_fingerprint()
			proxy = random.choice(proxies)
			response = requests.post(f"https://discord.com/api/v9/invites/{invite_code}", headers=headers, cookies=request_cookie(), proxies=proxy)
			if response.status_code == 200:
				print(f"{Fore.LIGHTGREEN_EX} [+] Token {tokens[x]} joined! {Fore.RESET}({Fore.LIGHTBLACK_EX}{invite_code}{Fore.RESET})")
				joincount = joincount + 1
			else:
				print(f"{Fore.LIGHTRED_EX} [!] Token {tokens[x]} didn't make it! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response.content}{Fore.RESET})")
			sleep(timeout)
		except Exception as e:
			print(e)
			pass
	for x in range(len(tokens)):
		try:
			headers["authorization"] = tokens[x]
			headers["x-fingerprint"] = request_fingerprint()
			response1 = requests.put(f"https://discord.com/api/v9/channels/{channelid}/messages/{messageid}/reactions/{emojihash}/%40me", headers=headers, cookies=request_cookie(), proxies=proxy)
			if response1.status_code == 204:
				print(f"{Fore.BLUE} [+] Token {tokens[x]} reacted! {Fore.RESET}({Fore.LIGHTBLACK_EX}{invite_code}{Fore.RESET})")
				reactioncount = reactioncount + 1
			else:
				print(f"{Fore.LIGHTRED_EX} [!] Token {tokens[x]} couldn't react! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response.content}{Fore.RESET})")
			sleep(timeout)
		except Exception as e:
			print(e)
			pass

	print(f"\n{Fore.LIGHTGREEN_EX} Logs: Tokens Joined {Fore.GREEN}{joincount}{Fore.LIGHTGREEN_EX} tokens | Tokens verified {Fore.GREEN}{reactioncount}{Fore.LIGHTGREEN_EX}")
	petc = input(f"\n{Fore.LIGHTWHITE_EX} Press ENTER to continue...")


def xpgainbot():
    messagecount = 0
    token = input(f"\n{Fore.RED} Token: {Fore.RESET}")
    channelid = input(f"{Fore.RED} Channel ID (Where to send the message): {Fore.RESET}")
    channelids2 = input(f"{Fore.RED} Do you want to send messages in multiple channel? [y/n]: {Fore.RESET}")
    if channelids2 == "y":
        channelid2 = input(f"{Fore.RED} Second Channel ID (Where to send the message): {Fore.RESET}")
    timeout = int(input(f"{Fore.RED} Timeout (Delay between messages): {Fore.RESET}"))
    print("\n")
    while True:
        headers["authorization"] = token
        headers["x-fingerprint"] = request_fingerprint()
        payload["content"] = sentance()
        payload2["content"] = sentance()
        response = requests.post(f"https://discord.com/api/v9/channels/{channelid}/messages", headers=headers, cookies=request_cookie(), data=payload)
        if channelids2 == "y":
            response2 = requests.post(f"https://discord.com/api/v9/channels/{channelid2}/messages", headers=headers, cookies=request_cookie(), data=payload2)
        if response.status_code == 200:
            messagecount = messagecount + 1
            print(f"{Fore.LIGHTGREEN_EX} [+] Successfully sent a message in Channel 1! {Fore.RESET}({Fore.LIGHTBLACK_EX}Message Count: {Fore.RED}{messagecount} {Fore.GREEN}| {Fore.LIGHTBLACK_EX}Message: {Fore.RED}{payload['content']}{Fore.RESET})")
            if channelids2 == "n":
                sleep(timeout)
        else:
            print(f"{Fore.LIGHTRED_EX} [!] Successfully didn't make it! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response.content}{Fore.RESET})")
            if channelids2 == "n":
                sleep(timeout)
        if channelids2 == "y":
            if response2.status_code == 200:
                messagecount = messagecount + 1
                print(f"{Fore.LIGHTGREEN_EX} [+] Successfully sent a message in Channel 2! {Fore.RESET}({Fore.LIGHTBLACK_EX}Message Count: {Fore.RED}{messagecount} {Fore.GREEN}| {Fore.LIGHTBLACK_EX}Message: {Fore.RED}{payload2['content']}{Fore.RESET})")
                sleep(timeout)
            else:
                print(f"{Fore.LIGHTRED_EX} [!] Token {token} didn't make it! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response.content}{Fore.RESET})")
                sleep(timeout)



######################################################################################################################################################################################################################################################################


def main():
	os.system('cls')

	title = """
	
 ██▒   █▓ ▄▄▄       ███▄    █  ██▓▄▄▄█████▓▓██   ██▓     ▄████  ██▓     ▒█████   █     █░    ▄▄▄       ██▓ ▒█████  
▓██░   █▒▒████▄     ██ ▀█   █ ▓██▒▓  ██▒ ▓▒ ▒██  ██▒    ██▒ ▀█▒▓██▒    ▒██▒  ██▒▓█░ █ ░█░   ▒████▄    ▓██▒▒██▒  ██▒
 ▓██  █▒░▒██  ▀█▄  ▓██  ▀█ ██▒▒██▒▒ ▓██░ ▒░  ▒██ ██░   ▒██░▄▄▄░▒██░    ▒██░  ██▒▒█░ █ ░█    ▒██  ▀█▄  ▒██▒▒██░  ██▒
  ▒██ █░░░██▄▄▄▄██ ▓██▒  ▐▌██▒░██░░ ▓██▓ ░   ░ ▐██▓░   ░▓█  ██▓▒██░    ▒██   ██░░█░ █ ░█    ░██▄▄▄▄██ ░██░▒██   ██░
   ▒▀█░   ▓█   ▓██▒▒██░   ▓██░░██░  ▒██▒ ░   ░ ██▒▓░   ░▒▓███▀▒░██████▒░ ████▓▒░░░██▒██▓     ▓█   ▓██▒░██░░ ████▓▒░
   ░ ▐░   ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░▓    ▒ ░░      ██▒▒▒     ░▒   ▒ ░ ▒░▓  ░░ ▒░▒░▒░ ░ ▓░▒ ▒      ▒▒   ▓▒█░░▓  ░ ▒░▒░▒░ 
   ░ ░░    ▒   ▒▒ ░░ ░░   ░ ▒░ ▒ ░    ░     ▓██ ░▒░      ░   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ▒ ░ ░       ▒   ▒▒ ░ ▒ ░  ░ ▒ ▒░ 
     ░░    ░   ▒      ░   ░ ░  ▒ ░  ░       ▒ ▒ ░░     ░ ░   ░   ░ ░   ░ ░ ░ ▒    ░   ░       ░   ▒    ▒ ░░ ░ ░ ▒  
      ░        ░  ░         ░  ░            ░ ░              ░     ░  ░    ░ ░      ░             ░  ░ ░      ░ ░ 
 """
	print(Fore.RED + title)
	login()
	time.sleep(5)
	os.system('cls')                                                                       
	print(f'''{Fore.RED}{title}
 {Fore.YELLOW}
 ╔══════════════════════════════════════════════╗
 ║  {Fore.LIGHTGREEN_EX}[1] NFT Invite Bot + Verification{Fore.YELLOW}           ║
 ║  {Fore.LIGHTGREEN_EX}[2] XP Gain Bot{Fore.YELLOW}                             ║
 ║                                              ║
 ║                                              ║
 ║                                              ║
 ║                                              ║
 ║                                              ║
 ║                                              ║
 ╚══════════════════════════════════════════════╝
''')

	option = input(f"{Fore.GREEN} Choose an option: {Fore.RESET}")

	if option == "1":
		nibv()
		main()
	if option == "2":
		xpgainbot()
		main()
main()
