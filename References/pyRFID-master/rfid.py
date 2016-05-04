#!/usr/bin/env python3

# SL030 RFID reader driver for skpang supplied SL030 Mifare reader
# Author:	Callan White
# Version:  0.1
# Date:		22/09/2013
# Modified and adapted from original by Thinking Binaries Ltd, David Whale
# Original can be found at http://www.skpang.co.uk/dl/rfid.py


# set to True to detect card presence by using GPIO
# set to False to detect card presence by reading card status

CFGEN_GPIO        = True


# Set to the GPIO required to monitor the tag detect (OUT) line
CFG_TAG_DETECT        = 4



if CFGEN_GPIO:
	import RPi.GPIO as GPIO

from quick2wire.i2c import I2CMaster, writing_bytes, reading
import time
import os 

ADDRESS           = 0x50
CMD_SELECT_MIFARE = 0x01
CMD_SECTOR_LOGIN  = 0x02
CMD_RD_DATA_BLOCK = 0x03
CMD_WR_DATA_BLOCK = 0x04
CMD_RD_VAL_BLOCK  = 0x05
CMD_INIT_BLOCK    = 0x06
CMD_WRITE_KEY     = 0x07
CMD_INC_VAL		  = 0x08
CMD_DEC_VAL		  = 0x09
CMD_CP_VAL		  = 0x0A
CMD_RD_DATA_PAGE  = 0x10 #Ultralight & NATG203
CMD_WR_DATA_PAGE  = 0x11 #Ultralight & NATG203
CMD_DOWNLOAD_KEY  = 0x12
CMD_SECTOR_LOGIN_KEY = 0x13
CMD_POWER_DOWN    = 0x50
CMD_GET_FIRMWARE  = 0xF0
WR_RD_DELAY       = 0.05

status = {
		0x00	:	"Operation succeeded",
		0x01	:	"No tag",
		0x02	:	"Login succeeded",
		0x03	:	"Login filed",
		0x04	:	"Read failed",
		0x05	:	"Write failed",
		0x06	:	"Unable to read after write",
		0x08	:	"Address overflow",
		0x09	:	"Download key failed",
		0x0A	:	"Collision occurred",
		0x0C	:	"Loading key failed",
		0x0D	:	"Not authenticated",
		0x0E	:	"Not a value block",
		0x0F	:	"Checksum error"
		}

def error(str):
	print("ERROR:" + str)

class SL030:
	def __init__(self):
		self.type = None
		self.uid  = None

		if CFGEN_GPIO:
			GPIO.setmode(GPIO.BCM)
			GPIO.setup(CFG_TAG_DETECT, GPIO.IN)

	def tag_present(self):
		if CFGEN_GPIO:
			return GPIO.input(CFG_TAG_DETECT) == False
		else:
			return self.select_mifare()

	def wait_tag(self):
		while not self.tag_present():
			time.sleep(0.01)

	def wait_notag(self):
		while self.tag_present():
			time.sleep(0.5)

	def validate_ver(self, ver):
		first = ver[0]
		if first != ord('S'):
			if first == ord('S') + 0x80:
				error("I2C clock speed too high, bit7 corruption")
				print("try: sudo modprobe -r i2c_bcm2708")
				print("     sudo modprobe i2c_bcm2708 baudrate=50000")
			else:
				error("unrecognised device")

	def tostr(self, ver):
		verstr = ""
		for b in ver:
			verstr += chr(b)
		return verstr

	def get_firmware(self):
		with I2CMaster() as master:
			# request firmware id read
			# <len> <cmd>
			master.transaction(writing_bytes(ADDRESS, 1, CMD_GET_FIRMWARE))
			time.sleep(WR_RD_DELAY)

			# read the firmware id back
			responses = master.transaction(reading(ADDRESS, 15))
			response = responses[0]
			# <len> <cmd> <ver...>
			len = response[0]
			cmd = response[1]
			ver = response[3:len]
			self.validate_ver(ver)
			
			return self.tostr(ver)

	def get_typename(self, type):
		if (type == 0x01):
			return "mifare 1k, 4byte UID"
		elif (type == 0x02):
			return "mifare 1k, 7byte UID"
		elif (type == 0x03):
			return "mifare UltraLight, 7 byte UID"
		elif (type == 0x04):
			return "mifare 4k, 4 byte UID"
		elif (type == 0x05):
			return "mifare 4k, 7 byte UID"
		elif (type == 0x06):
			return "mifare DesFire, 7 byte UID"
		elif (type == 0x0A):
			return "other"
		else:
			return "unknown:" + str(type)

	def select_mifare(self):
		with I2CMaster() as master:
			# select mifare card
			# <len> <cmd> 
			master.transaction(writing_bytes(ADDRESS, 1, CMD_SELECT_MIFARE))
			time.sleep(WR_RD_DELAY)

			# read the response
			responses = master.transaction(reading(ADDRESS, 15))
			response = responses[0]
			# <len> <cmd> <status> <UUID> <type>
			len    = response[0]
			cmd    = response[1]
			status = response[2]

			if (status != 0x00):
				self.uid  = None
				self.type = None
				return False 

			# uid length varies on type, and type is after uuid
			uid       = response[3:len]
			type      = response[len]
			self.type = type
			self.uid  = uid
			return True

	def get_uid(self):
		return self.uid

	def get_uidstr(self):
		uidstr = ""
		for b in self.uid:
			uidstr += "%02X" % b
		return uidstr

	def get_type(self):
		return self.type
		
	#Above part of class courtesy of David Whale, Thinking Binary Ltd
	
	def sector_login(self,sector,key_type,a,b,c,d,e,f):
		with I2CMaster() as master:
			#<len><cmd><sector><key_type><key>
			master.transaction(writing_bytes(ADDRESS,9,CMD_SECTOR_LOGIN,sector,key_type,a,b,c,d,e,f))
			time.sleep(WR_RD_DELAY)
			
			responses = master.transaction(reading(ADDRESS,15))
			response = responses[0]
			#<len><cmd><status>
			
			print("LEN {} CMD {} STATUS {} OTHER {} {} {}".format(response[0],response[1],response[2],response[3],response[4],response[5]))
	
	def read_block(self,block):
		with I2CMaster() as master:
			#<len><cmd><block>
			master.transaction(writing_bytes(ADDRESS,2,CMD_RD_DATA_BLOCK,block))
			time.sleep(WR_RD_DELAY)
			
			responses = master.transaction(reading(ADDRESS,19))
			response = responses[0]
			#<len><cmd><status><data>
			r_code = status[response[2]]
			#("LEN {} CMD {} STATUS {} DATA {}".format(response[0],response[1],response[2],response[6]))			
			print("\nBLOCK {} - {} : ".format(block,r_code),end="")
			for i in range(3,19):
				print("%02x"%response[i],end=" ")
			
	def read_page(self,page):
		with I2CMaster() as master:
			#<len><cmd><page>
			master.transaction(writing_bytes(ADDRESS,2,CMD_RD_DATA_PAGE,page))
			time.sleep(WR_RD_DELAY)
			
			responses = master.transaction(reading(ADDRESS,7))
			response = responses[0]
			r_code = status[response[2]]
			
			#output hex and ASCII text
			print("\nPAGE {} - {} : ".format(page,r_code),end="")
			for i in range(3,7):
				print("%02x"%response[i],end=" ")
			for i in range(3,7):
				print(chr(response[i]),end=" ")
	
	def write_page(self,page,a,b,c,d):
		with I2CMaster() as master:
			#<len><cmd><page><data>
			master.transaction(writing_bytes(ADDRESS,6,CMD_WR_DATA_PAGE,page,a,b,c,d))
			time.sleep(WR_RD_DELAY)
			#<len><cmd><status><data>
			responses = master.transaction(reading(ADDRESS,15))
			response = responses[0]
			r_code = status[response[2]]
			print("WRITE PAGE: {} - {} : {} {} {} {}".format(page,r_code,"%02x"%response[3],"%02x"%response[4],"%02x"%response[5],"%02x"%response[6]))
	
	def format(self):
		for i in range(6,40):
			self.write_page(i,0,0,0,0)
			
	def dump(self):
		for i in range(42):
			self.read_page(i)
	
	def dump_block(self):
		for i in range(10):
			self.read_block(i)
			
	def write_string(self,string):
		if len(string) > 136:
			print("String too large")
			return False
	
		#pad string with blank spaces (saves preformatting the card)
		string = string.ljust(136)
		
		#REDO THIS - JUST WRITE 0s TO PAD ENTIRE CARD (SAVES PREFORMAT)
		offset = 0
		for i in range(6,40):
			a=string[offset]
			b=string[offset+1]
			c=string[offset+2]
			d=string[offset+3]
			self.write_page(i,ord(a),ord(b),ord(c),ord(d))
			print("{} {} {} {}".format(ord(a),ord(b),ord(c),ord(d)))
			offset=offset+4
	
		return True
	
##########################################################################
# Fix the baud rate of the I2C driver.
# The combination of the SL030 and the Raspberry Pi I2C driver
# causes some corruption of the data at the default baud rate of
# 100k. Until this problem is completely fixed, we just change the
# baud rate here to a known working rate. Interestingly, it fails at
# 90k but works at 200k and 400k.

def fixrate():
	newspeed = 200000
	os.system("sudo modprobe -r i2c_bcm2708")
	os.system("sudo modprobe i2c_bcm2708 baudrate=" + str(newspeed))
	time.sleep(1.0)



###########################################################################
# Simple test program
#
# Just run rfid.py to run this test program against the driver.
#
# For your own application, copy these lines into a new file
# and put this at the top of your new file:
#
# import rfid
#
# Then modify your application to suit


# fill in this map with your card id's

cards = {
	"04A10C1A3B2B84"	:	"TEST NFC GREEN",
	"04B2291A3B2B80"	:	"TEST NFC YELLOW"
	}

def example():
	rfid = SL030()
	fw = rfid.get_firmware()
	print("RFID reader firmware:" + fw)
	print()

	while True:
		rfid.wait_tag()
		print("card present")

		if rfid.select_mifare():
			type = rfid.get_type()
			print("type:" + rfid.get_typename(type))
			#rfid.write_string('The quick brown fox jumps over the lazy dog')
			#rfid.format()
			#rfid.dump()
			#figure out what we're doing
			input_var = input("Choose an option\n1) format\n2) dump")
			if int(input_var)==1:
				rfid.format()
			elif int(input_var)==2:
				rfid.dump()
			elif int(input_var)==3:
				rfid.write_string("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN THE FOX GETS SAVAGED BY THE NOT SO LAZY DOG BECAUSE THAT DOG IS A REAL ASSHOLE")
			elif int(input_var)==4:
				rfid.dump_block()
			elif int(input_var)==5:
				rfid.sector_login(0x04)
			id = rfid.get_uidstr()
			try:
				user = cards[id]
				print(user)
				#os.system("aplay " + user)
			except KeyError:
				print("Unknown card:" + id)

		rfid.wait_notag()
		print("card removed")
		print()

if __name__ == "__main__":
	fixrate()
	example()