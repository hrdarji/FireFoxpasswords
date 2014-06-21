FireFoxpasswords
================

Fetching saved mozilla firefox passwords

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
