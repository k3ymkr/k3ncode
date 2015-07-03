#!/usr/bin/env python

import random,re,sys
import base64, string
import M2Crypto, hashlib, m2secret,argparse


class InvalidInput(Exception):
	pass
	

class k3encrypt:
	input=""

	def __init__(self,input):
		self.input=input

	def fromanytonum(self,base):
		self.input=str(self.fromany(self.input,base))

	def frombin(self):
		self.fromanytonum(2)

	def toanyfromstr(self,base):
		out=""
		for a in self.input:
			out+=self.toany(str(ord(a)),base)
		self.input=out
	
	def tobin7fromstr(self):
		out=""
		for a in self.input:
			tmp=self.toany(str(ord(a)),2)
			out+=tmp[1:]
		self.input=out

	def tobase64(self,size=64):
		if (size==32):
			self.input=base64.b32encode(self.input)
		else:
			self.input=base64.b64encode(self.input)
	
	def frombase64(self,size=64):
		if (size==32):
			self.input=base64.b32decode(self.input)
		else:
			self.input=base64.b64decode(self.input)
		

	def ceaser(self,chars=13,rev=0):
		out=""
		for a in self.input:
			num=ord(a)
			for b in (64,96):
				if num>b and num<(b+27):
					if rev == 0:
						num+=chars
						if num>(b+26):
							num-=26
					else:
						num-=chars
						if num<(b+1):
							num+=26
			out+=chr(num)
			
		self.input=out


	def fromanytostr(self,base):
		out=""
		inc=""
		if (base<2) or (base>36):
			raise k3encrypt.InvalidInput()

		count=0
		val=1
		while(val<256):
			count+=1
			val*=base
		val=count
		count=0
		for a in self.input.upper():
			if not(a.isalnum()) and re.match('[^\s]',a):
				raise k3encrypt.InvalidInput()
			if a.isdigit():
				if int(a) >= base:
					raise k3encrypt.InvalidInput()
				inc+=a
			elif(a.isalpha()):
				if (ord(a)-64) >= base:
					raise k3encrypt.InvalidInput()
				inc+=a

				

		while(len(inc)>0):
			tmp=inc[0:val]
			inc=inc[val:]
			count=self.fromany(tmp,base)
			if (count>=256):
				raise k3encrypt.InvalidInput()
			out+=chr(count)
		self.input=out
				
		
			


	def frombin7tostr(self):
		binary=""
		out=""
		for a in self.input:
			if (not(re.match('[01\s]',a))):
				raise k3encrypt.InvalidInput()
			elif (re.match('[01]',a)):
				binary+=a
		while (len(binary)%7):
			binary="0"+binary
		while(len(binary)>0):
			tmp=binary[0:7]
			binary=binary[7:]
			count=self.fromany(tmp,2)
			out+=chr(count)
		self.input=out

	def fromany(self,inc,base):
		out=0
		ninc=""
		for a in inc:
			if (not(re.match('[A-Za-z0-9\s]',a))):
				raise k3encrypt.InvalidInput()
			elif (re.match('[A-Za-z0-9]',a)):
				a=a.upper()
				ninc+=a
		inc=ninc

		size=base**(len(inc)-1)
		for a in inc:
			tout=a
			if (a.isdigit()):
				tout=int(a)
			else:
				tout=ord(a)-64
			out+=tout*size
			size/=base
		return out	

	def morse(self,rev=0):
		out=""
		order={".-":"A","-...":"B","-.-." : "C","-.." : "D","." : "E","..-." : "F","--." : "G","...." : "H",".." : "I",".---" : "J","-.-" : "K",".-.." : "L","--" : "M","-." : "N","---" : "O",".--." : "P","--.-" : "Q",".-." : "R","..." : "S","-" : "T","..-" : "U","...-" : "V",".--" : "W","-..-" : "X","-.--" : "Y","--.." : "Z","-----" : "0",".----" : "1","..---" : "2","...--" : "3","....-" : "4","....." : "5","-...." : "6","--..." : "7","---.." : "8","----." : "9",".-.-.-" : "FULLSTOP","--..--" : "COMMA","..--.." : "QUERY"}
		if rev==1:
			for a in re.split('\s+',self.input):
				try:
					out+=order[a]
				except:
					out+=a
		else:
			neworder={}
			for a in order.keys():
				neworder[order[a]]=a
			for a in self.input:
				try:
					a=a.upper()
					out+="%s "%neworder[a]
				except:
					out+=a
		self.input=out
				
			
			

	def toany(self,inc,base):
		"""I want a base10 number"""
		if (base>36) or (base<2):
			raise k3encrypt.InvalidInput()
		out=""
		ninc=""
		for a in inc:
			if (not(re.match('\d+',a))):
				raise k3encrypt.InvalidInput()
			else:
				ninc+=a
		inc=int(ninc)
		size=base
		while size<=inc:
			size*=base
		size/=base
		while size>=1:
			t=inc/size
			inc-=t*size
			size/=base
			if t<10:
				out+=str(t)
			else:
				out+=chr(t+55)
		size=base
		leng=1
		while size**leng<=255:
			leng+=1
		while len(out)<leng:
			out="0%s"%out
		return out
			

	def vigenere(self,key,rev=0):
		out=""
		keypos=0
		key=key.lower()
		for a in self.input:
			num=ord(a)
			for b in (64,96):
				if num>b and num<(b+27):
					if rev == 0:
						num+=ord(key[keypos])-97
						if num>(b+26):
							num-=26
					else:
						num-=ord(key[keypos])-97
						if num<(b+1):
							num+=26
					keypos+=1
					if keypos==len(key):
						keypos=0
			out+=chr(num)
		self.input=out


	def playfair(self,keyBase,rev=0,ijblock=1):
		output=""
		keyBase+=string.letters
		keyBase=keyBase.upper()
		ks=""
		count=0
		for a in keyBase:
			if count<26:
				if ijblock==1:
					if a=='J':
						a='A'
				elif ijblock==0:
					if a=='Q':
						a='A'
				elif ijblock==2:
					if a=='Z':
						a='A'
				if ks.find(a) == -1:
					ks+=a
					count+=1
		pos=[]
		count=0
		for a in self.input:
			lookup=a.upper()
			if ijblock==0:
				if lookup=='Q':
					lookup='P'
			elif ijblock==1: 
				if lookup=='J':
					lookup='I'
			elif lookup=='Z':
				lookup='Y'

				
			b=ks.find(lookup)
			if b!=-1:
				pos.append([count,a,b/5,b%5])
			count+=1
		if len(pos)%2==1:
			self.input+=ks[len(ks)-1]
			pos.append([count,ks[len(ks)-1],4,4])
		output=list(self.input)
		for a in range(0,len(pos)-1,2):
			if pos[a][2]==pos[a+1][2]:
				if rev==1:
					for b in range(a,a+2):
						pos[b][3]-=1
						if pos[b][3]<0:
							pos[b][3]=4
				else:
					for b in range(a,a+2):
						pos[b][3]+=1
						if pos[b][3]>4:
							pos[b][3]=0
				
			elif pos[a][3]==pos[a+1][3]:
				if rev==1:
					for b in range(a,a+2):
						pos[b][2]-=1
						if pos[b][2]<0:
							pos[b][2]=4
				else:
					for b in range(a,a+2):
						pos[b][2]+=1
						if pos[b][2]>4:
							pos[b][2]=0
			else:
				pos[a][3]^=pos[a+1][3]
				pos[a+1][3]^=pos[a][3]
				pos[a][3]^=pos[a+1][3]
			

			for b in range(a,a+2):
				rep=ks[pos[b][2]*5+pos[b][3]]
				if pos[b][1].islower():
					rep=rep.lower()
				output[pos[b][0]]=rep
		self.input="".join(output)
				
					
			

	def m2crypto(self,alg,key,rev=0,iv=None):
		if iv is None:
			iv = '\0' * 16
		else:
			iv = base64.b64decode(iv)
		rev=1-rev
		c=M2Crypto.EVP.Cipher(alg, key=key, iv=iv, op=rev)
		o=c.update(self.input)
		o=o+c.final()
		del c
		self.input=o

	def m2mzsecret(self,alg,key,rev=0):
		c=m2secret.Secret('\0'*32,'\0'*32,None,1000,alg)
		if rev==0:
			c.encrypt(self.input,key)
			self.input=c.serialize().split('|')[2]
			self.input=m2secret.unhexlify(self.input)
		else:
			bases='0000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000'
			b="%s|%s"%(bases,m2secret.hexlify(self.input))
			c.deserialize(b)
			self.input=c.decrypt(key)


	def aes256(self,key,rev=0,iv=None):
		self.m2mzsecret('aes_256_cbc',key,rev)

		
	def des(self,key,rev=0,iv=None):
		self.m2mzsecret('des_ede_cbc',key,rev)

	def des3des(self,key,rev=0,iv=None):
		self.m2mzsecret('des_ede3_cbc',key,rev)

		
		

	def keyedceaser(self,key,rev=0):
		key=key.lower()
		rkey=[]
		fkey={}
		rkeykey=""
		out=""
		for a in key:
			if rkeykey.find(a)==-1:
				rkeykey+=a
		for a in range(97,123):
			tadd=chr(a)
			if rkeykey.find(tadd)==-1:
				rkeykey+=tadd
		for a in rkeykey:
			rkey.append(ord(a))
		c=0
		for a in range(0,26):
			fkey[ord(rkeykey[a])-97]=97+a
		for a in self.input:
			num=ord(a)
			for b in (64,96):
				if num>b and num<(b+27):
					if rev==0:
						num=b+rkey[num-b-1]-96
					else:
						num=b+fkey[num-b-1]-96
			out+=chr(num)
		self.input=out
			

	def urlreplace(self,into):
		out=""
		for a in into.group():
			if a != '%':
				out+=a
		return chr(self.fromany(out,16))

				
	def urlencode(self,rev=0):
		out=""
		if rev==0:
			for a in self.input:
				if not re.match('[a-zA-Z0-9-_.~]',a):
					a='%'+self.toany(str(ord(a)),16)
				out+=a
			self.input=out
		else:
			out=re.sub('\+',' ',self.input)
			out=re.sub('%([a-fA-F0-9]{2,2})',self.urlreplace,out)
			out=re.sub('<!--(.|\n)*-->','',out)
			self.input=out

			

		
	

	def __str__(self):
		return self.input
		
		
if (__name__ == "__main__"):
	encodes=('ascii','hex','binary','binary7','oct','base64','base32','urlencode','morse')
	encrypts=('ceaser','keyceaser','aes256','vigenere','playfair','des','3des')
	ap=argparse.ArgumentParser(description='An encoding/encryption tool',usage="Usage: %s [-k key] [-e cipher] [-d cipher] [ -i encode ] [ -o encode ] [-h] "%(sys.argv[0]),)
	ap.add_argument('-k','--key',type=str,help="encryption key")
	ap.add_argument('-e','--encrypt',type=str,help="Cipher used to encrypt: %s"%encrypts.__str__())
	ap.add_argument('-d','--decrypt',type=str,help="Cipher used to decrypt: %s"%encrypts.__str__())
	ap.add_argument('-i','--decode',type=str,help="Encoding technic on input: %s"%encodes.__str__())
	ap.add_argument('-o','--encode',type=str,help="Encoding technic on output: %s"%encodes.__str__())
	args=ap.parse_args()
	inc=""
	for a in sys.stdin.readlines():
		inc+=a
	output=k3encrypt(inc)
	cont=1
	try:
		if args.decode != 'None' and args.decode != "ascii":
			if args.decode == "hex":
				output.fromanytostr(16)
			if args.decode == "binary":
				output.fromanytostr(2)
			if args.decode == "binary7":
				output.frombin7tostr()
			if args.decode == "oct":
				output.fromanytostr(8)
			if args.decode == "base64":
				output.frombase64()
			if args.decode == "base32":
				output.frombase64(32)
			if args.decode == "urlencode":
				output.urlencode(1)
			if args.decode == "morse":
				output.morse(1)
	except: 
		output="Decoding Error"
		cont=0
	if args.encrypt:
		if args.key:
			key=args.key
			encrypt=args.encrypt
			encmode=0
			if args.decrypt:
				output="Can't encrypt and decrypt in the same pass"
				cont=0
		else:
			output="Encryption request with no key"
			cont=0
	if args.decrypt:
		if args.key:
			key=args.key
			encrypt=args.decrypt
			encmode=1
		else:
			output="Decryption request with no key"
			cont=0
	if cont==1:
		try:
			if args.encrypt != None and args.encrypt != "none":
				if args.encrypt == "ceaser":
					output.ceaser(int(key),encmode)
				if args.encrypt == "keyceaser":
					output.keyedceaser(key,encmode)
				if args.encrypt == "aes256":
					output.aes256(key,encmode)
				if args.encrypt == "vigenere":
					output.vigenere(key,encmode)
				if args.encrypt == "playfair":
					output.playfair(key,encmode,ijblock)
				if args.encrypt == "des":
					output.des(key,encmode)
				if args.encrypt == "3des":
					output.des3des(key,encmode)
		except:
			output="Encryption Error"
			cont=0

	if cont==1:
		try:
			if args.encode != None and args.encode != "ascii":
				if args.encode == "hex":
					output.toanyfromstr(16)
				if args.encode == "binary":
					output.toanyfromstr(2)
				if args.encode == "binary7":
					output.tobin7fromstr()
				if args.encode == "oct":
					output.toanyfromstr(8)
				if args.encode == "base64":
					output.tobase64()
				if args.encode == "base32":
					output.tobase64(32)
				if args.encode == "urlencode":
					output.urlencode()
				if args.encode == "morse":
					output.morse()
		except:
			output="Encoding Error"

	print output
