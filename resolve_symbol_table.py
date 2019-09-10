import struct
import argparse

# Setup arguments
parser = argparse.ArgumentParser(description='Reorder string table from symbol table offsets.')
parser.add_argument('-s', dest='sym_path', help='File path to symbol table dump file.', required=True)
parser.add_argument('-t', dest='str_path', help='File path to string table dumpt file.', required=True)

# Parse out arguments
args = parser.parse_args()
ssh_ip = args.ssh_ip
global_protect_ip = args.global_protect_ip
password = args.ssh_pw

# Open symbol table dump
sym_path = args.sym_path
f = open(sym_path, 'rb')
table_lookup_bin = f.read()
f.close()

# Open string table dump
str_path = args.str_path
f = open(str_path, 'rb')
func_str = f.read()
f.close()

marker = 0
while marker < len(table_lookup_bin):
    offset = table_lookup_bin[marker:marker+4]
    idx = struct.unpack(">I", offset)[0]
    #print "String Table Offset: %s" % hex(idx)
    if idx > 0:
        cropped_buf = func_str[idx:]
        #print cropped_buf
        z_idx = cropped_buf.find("\x00")
        #print "Zero Offset: %s" % hex(z_idx)
        if z_idx != -1:
            func = cropped_buf[:z_idx]
            print func
    else:
        print "***********************"

    marker += 24
    #raw_input()