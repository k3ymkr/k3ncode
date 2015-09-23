#!/usr/bin/env python

import random,re,sys
import base64, string
import hashlib,argparse


class InvalidInput(Exception):
	pass
	

class k3encrypt:
	encodesin={"ascii":"None","hex": 'fromhex',"binary": "frombin","oct": "fromoct","binary7": "frombin7tostr","base64": "frombase64","base32": "frombase32","urlencode":"fromurlencode","morse": "frommorse", "flip": "flip","upper": "upper","lower": "lower","atbash":"atbash","rot13": "ceaser","uudecode":"uudecode","htmlentities":"fromhtmlentities"}
	encodesout={"ascii":"None","hex": 'tohex',"binary": "tobin","oct": "tooct","binary7": "tobin7fromstr","base64": "tobase64","base32": "tobase32","urlencode":"tourlencode","morse": "tomorse", "flip": "flip","upper": "upper","lower": "lower","atbash":"atbash","rot13": "ceaser","md5":"md5","sha1":"sha1","sha256":"sha256","sha512":"sha512","uuencode":"uuencode","htmlentities":"tohtmlentities"}
	encrypts={'ceaser':'ceaser','keyceaser':'keyceaser','vigenere':'vigenere','playfair':'playfair','xor':'xor'}

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

	def tohex(self):
		self.toanyfromstr(16)

	def tooct(self):
		self.toanyfromstr(8)

	def tobin(self):
		self.toanyfromstr(2)


	
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

	def frombase32(self):
		self.frombase64(32)
	
	def flip(self):
		new=""
		for a in self.input:
			new="%s%s"%(a,new)
		self.input=new


	def tohtmlentities(self):
		cmap={'"':'&quot;','&':'&amp;',"'":'&apos;','<':'&lt;','>':'&gt;',' ':'&nbsp;'}
		ret=""
		for a in self.input:
			if (cmap.has_key(a)):
				ret+=cmap[a]
			else:
				b=ord(a)
				ret+='&#%d;'%b
		self.input=ret

	def fromhtmlentities(self):
		cmap={'&nbsp;':' ', '&quot;':'"', '&apos;':"'", '&amp;':'&', '&lt;':'<', '&gt;':'>'}
		s=self.input
		ret=""
		while len(s)>0:
			m=re.match('(&.*?;)',s,flags=re.I|re.S)
			if m:
				n=m.group(1)
				if cmap.has_key(n):
					ret+=cmap[n]
				else:
					m=re.match('&#(.*?);',s,flags=re.I|re.S)
					if m:
						n=m.group(1)
						if n[0]=='x':
							ret+=chr(self.fromany(n[1:],16))
						elif n.isdigit():
							ret+=chr(int(n))
						else:
							ret+=n
				c=re.compile('^&.*?;',flags=re.I|re.S)
				s=re.sub(c,'',s)
			else:
				ret+=s[0]
				if len(s)>0:
					s=s[1:]
				else:
					s=""
		self.input=ret
		
				
			
	
	def uuencode(self):
		out="begin 000 -\n"
		i=self.input
		c=0
		s=32
		l=""
		isize=len(i)
		while(c<isize):
			t=""
			for a in range(c,c+3):
				if a<isize:
					 t+=self.toany(str(ord(i[a])),2)
					 s+=1
			c+=3
			for a in range(0,4):
				l+=chr(32+self.fromany(t[a*6:a*6+6],2))
			if (c%45==0):
				out+="%s%s\n"%(chr(s),l)
				l=""
				s=32
		if l!="":
			out+="%s%s\n"%(chr(s),l)
		out+='`'
		out+="\nend\n"
		self.input=out
			
	def uudecode(self):
		i=re.sub('^begin .*?\n','',self.input)	
		out=""
		m=re.match('^(.*?)\n',i)
		while(m.group(1)!="end"):
			l=""
			v=m.group(1)
			i=re.sub('^.*?\n','',i)
			v=v[1:]
			isize=len(v)
			c=0
			while(c<isize):
				t=""
				for a in range(c,c+4):
					if a<isize:
						t+=self.toany(str(ord(v[a])-32),2)[2:]
				c+=4
				for a in range(0,3):
					out+=chr(self.fromany(t[a*8:a*8+8],2))
			m=re.match('^(.*?)\n',i)
		self.input=out

	def ceaser(self,chars=13,rev=0):
		out=""
		chars=int(chars)
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

	def fromhex(self):
		self.fromanytostr(16)
				
	def frombin(self):
		self.fromanytostr(2)
				
	def fromoct(self):
		self.fromanytostr(8)
				
	def hash(self,alg):
		t=hashlib.new(alg)
		t.update(self.input)
		self.input=t.hexdigest()
		self.input+="\n"

	def md5(self):
		self.hash("md5")
	def sha1(self):
		self.hash("sha1")
	def sha256(self):
		self.hash("sha256")
	def sha512(self):
		self.hash("sha512")
		
		
			
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

	def frommorse(self):
		self.morse(1)
				
	def tomorse(self):
		self.morse()
				
			
			

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

	def xor(self,key,rev=0):
		#Rev is pointless, but I kept it available for compatability

		out=""
		keyloop=0
		for a in self.input:
			out+=chr(ord(a)^ord(key[keyloop]))
			keyloop+=1
			if keyloop == len(key):
				keyloop=0
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


	def atbash(self):
		ret=""
		for a in self.input:
			b=ord(a)
			if b>96 and b <123:
				ret+=chr(96+(123-b))
			elif b>64 and b <91:
				ret+=chr(64+(91-b))
			else:
				ret+=a
		self.input=ret
			
	def lower(self):
		self.input=self.input.lower()
	
	def upper(self):
		self.input=self.input.upper()


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

			
	def fromurlencode(self):
		self.urlencode(1)
	
	def tourlencode(self):
		self.urlencode()


		
	

	def __str__(self):
		return self.input
		
		
if (__name__ == "__main__"):
	
	#Add xor, shaX, md5 and uuencoding
	ap=argparse.ArgumentParser(description='An encoding/encryption tool',usage="Usage: %s [-k key] [-e cipher] [-d cipher] [ -i encode ] [ -o encode ] [-h] "%(sys.argv[0]),)
	ap.add_argument('-k','--key',type=str,help="encryption key")
	ap.add_argument('-e','--encrypt',type=str,help="Cipher used to encrypt: %s"%k3encrypt.encrypts.keys().__str__())
	ap.add_argument('-d','--decrypt',type=str,help="Cipher used to decrypt: %s"%k3encrypt.encrypts.keys().__str__())
	ap.add_argument('-i','--decode',type=str,help="Encoding technic on input: %s"%k3encrypt.encodesin.keys().__str__())
	ap.add_argument('-o','--encode',type=str,help="Encoding technic on output: %s"%k3encrypt.encodesout.keys().__str__())
	args=ap.parse_args()
	inc=""
	for a in sys.stdin.readlines():
		inc+=a
	inc=inc.rstrip()
	output=k3encrypt(inc)
	cont=1
	if args.decode != None and args.decode != "ascii":
		if k3encrypt.encodesin.has_key(args.decode):
			res=getattr(output,k3encrypt.encodesin[args.decode])
			res()
		else:
			output="Invalid decode: %s"%args.decode
			cont=0
	encrypt=None
	if args.encrypt:
		if args.key:
			key=args.key
			encrypt=args.encrypt
			encmode=0
			if args.decrypt:
				print >>sys.stderr,"Can't encrypt and decrypt in the same pass"
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
			print >>sys.stderr,"Decryption request with no key"
			cont=0
	if cont==1:
		if encrypt != None and encrypt != "none":
			if k3encrypt.encrypts.has_key(encrypt):
				res=getattr(output,k3encrypt.encrypts[encrypt])
				res(key,encmode)
			else:
				output="Invalid encrypt/decrypt: %s"%encrypt
				cont=0
				
	if cont==1:
		if args.encode != None and args.encode != "ascii":
			if k3encrypt.encodesout.has_key(args.encode):
				res=getattr(output,k3encrypt.encodesout[args.encode])
				res()
			else:
				print >>sys.stderr,"Invalid decode: %s"%args.encode
				cont=0

	if cont==1:
		#sys.stdout.write(output.__str__())
		print output
