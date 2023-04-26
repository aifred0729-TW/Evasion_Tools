#!/usr/bin/python

import random
import string

banner = """
  ██████  ██░ ██ ▓█████  ██▓     ██▓     ▄████▄   ▒█████  ▓█████▄ ▓█████ 
▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    ▒██▀ ▀█  ▒██▒  ██▒▒██▀ ██▌▓█   ▀ 
░ ▓██▄   ▒██▀▀██░▒███   ▒██░    ▒██░    ▒▓█    ▄ ▒██░  ██▒░██   █▌▒███   
  ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    ▒▓▓▄ ▄██▒▒██   ██░░▓█▄   ▌▒▓█  ▄ 
▒██████▒▒░▓█▒░██▓░▒████▒░██████▒░██████▒▒ ▓███▀ ░░ ████▓▒░░▒████▓ ░▒████▒
▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░░ ░▒ ▒  ░░ ▒░▒░▒░  ▒▒▓  ▒ ░░ ▒░ ░
░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░  ░  ▒     ░ ▒ ▒░  ░ ▒  ▒  ░ ░  ░
░  ░  ░   ░  ░░ ░   ░     ░ ░     ░ ░   ░        ░ ░ ░ ▒   ░ ░  ░    ░   
      ░   ░  ░  ░   ░  ░    ░  ░    ░  ░░ ░          ░ ░     ░       ░  ░
                                        ░                  ░             
▓█████  ▄████▄   ██▀███ ▓██   ██▓ ██▓███  ▄▄▄█████▓▓█████  ██▀███        
▓█   ▀ ▒██▀ ▀█  ▓██ ▒ ██▒▒██  ██▒▓██░  ██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒      
▒███   ▒▓█    ▄ ▓██ ░▄█ ▒ ▒██ ██░▓██░ ██▓▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒      
▒▓█  ▄ ▒▓▓▄ ▄██▒▒██▀▀█▄   ░ ▐██▓░▒██▄█▓▒ ▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄        
░▒████▒▒ ▓███▀ ░░██▓ ▒██▒ ░ ██▒▓░▒██▒ ░  ░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒      
░░ ▒░ ░░ ░▒ ▒  ░░ ▒▓ ░▒▓░  ██▒▒▒ ▒▓▒░ ░  ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░      
 ░ ░  ░  ░  ▒     ░▒ ░ ▒░▓██ ░▒░ ░▒ ░         ░     ░ ░  ░  ░▒ ░ ▒░      
   ░   ░          ░░   ░ ▒ ▒ ░░  ░░         ░         ░     ░░   ░       
   ░  ░░ ░         ░     ░ ░                          ░  ░   ░           
       ░                 ░ ░                                        
                                                _                              
                                      |_       |_)  _   _|   |\/|  _   _       
                                      |_) \/   | \ (/_ (_|   |  | (/_ (_) \/\/ 
                                          /                                    
"""
print(banner)

mode_arr = [['Caesar', 1], ['XOR', 2], ['New Code', 3]]

def check_format():
    while True:
        code_format = input("[*] Input your shellcode format : ").lower()
        if code_format in ["csharp", "c"]:
            return code_format
        else:
            print("[!] Unsupported format")

def recv_csharp(shellcode):
    result = []
    for i in shellcode:
        if "{" in i:
            i = i.split("{")[1]
        elif "}" in i:
            i = i.split("}")[0]
        tmp_line = i.strip(",").split(",")
        tmp_int = [int(a, 16) for a in tmp_line]
        result.append(tmp_int)
    return result

def recv_c(shellcode):
    result = []
    for i in shellcode:
        i = i.strip(";").strip('"').split("\\x")
        i.remove("")
        tmp_line = ["0x"+a for a in i]
        tmp_int = [int(a,16) for a in tmp_line]
        result.append(tmp_int)
    return result

def get_shellcode():
    print("====================================")
    mode = check_format()
    print("[*] Input your shellcode until enter \"done\"")
    shellcode = []
    while True:
        data = input()
        if data == "done":
            break
        else:
            shellcode.append(data)
    if mode == "csharp":
        shellcode = recv_csharp(shellcode)
    elif mode == "c":
        shellcode = recv_c(shellcode)
    return shellcode, mode

def caesar(shellcode, mode):
    offset = random.randint(2, 24)
    print("[*] Module : Caesar Encode")
    print("[*] Generate offset " + str(offset))
    print("[*] Here is the decrypt code")
    if mode == "csharp":
        print("for (int i = 0; i < buf.Length; i++){buf[i] = (byte)(((uint)buf[i] - " + str(offset) + ")& 0xFF);}")
    if mode == "c":
        print("笑死 我還沒做這功能")
    result = []
    for i in shellcode:
        encrypt_line = [(a + offset) % 256 for a in i]
        result.append(encrypt_line)
    return result

def xor(shellcode, mode):
    letters = string.ascii_lowercase
    if mode == "csharp":
        key = ''.join(random.choice(letters) for i in range(12))
    elif mode == "c":
        key = ''.join(random.choice(letters) for i in range(14))
    key_list = [ord(a) for a in key]
    result = []
    print("[*] Module : XOR")
    print("[*] Your XOR key is " + key)
    print("[*] Here is the decrypt code")
    if mode == "csharp":
        print('string meow = "' + key + '";')
        print('for (int i = 0; i < 6; i++){buf[i] = (byte)((uint)buf[i] ^ (uint)meow[i]);}')
        print('for (int i = 6; i < buf.Length; i++){buf[i] = (byte)((uint)buf[i] ^ (uint)meow[(i - 6) % 12]);}')
    elif mode == "c":
        print('const char xor_key[15] = {"' + key + '"};')
        print('int arraysize = (int) sizeof(buf);')
        print('for (int i=0; i<arraysize -1; i++){buf[i] = buf[i]^xor_key[i % 14];}')
    for i in shellcode:
        tmp = [i[j] ^ key_list[j] for j in range(len(i))]
        result.append(tmp)
    return result

def show_shellcode(data, mode):
    print("[*] Here is your shellcode")
    count = 0
    shellcode = []
    for i in data:
        hex_data = [hex(x) for x in i]
        if mode == "csharp":
            full_hex = ['0x' + s[2:].zfill(2) for s in hex_data]
        elif mode == "c":
            full_hex = ['\\x' + s[2:].zfill(2) for s in hex_data]
        count += len(full_hex)
        shellcode.append(full_hex)
    if mode == "csharp":
        print("byte[] buf = new byte[" + str(count) + "] {", end="")
        end = 0
        for i in shellcode:
            for j in range(len(i)):
                end += 1
                if end == count:
                   print(i[j], end='};')
                   break
                else:
                   print(i[j], end=',')
            print()
    elif mode == "c":
        print("unsigned char buf[] =")
        for i in shellcode:
            print('"', end='')
            for j in range(len(i)):
                print(i[j], end='')
            print('"')
        print(';')

shellcode, mode = get_shellcode()
while True:
    print("=======================================================")
    print("{:<10}{:2}".format("Modules", "ID"))
    print("{:<10}{:2}".format("-"*8, "-"*3))
    for i in mode_arr:
      print("{:<10}{:<2}".format(i[0], i[1]))
    try:
        id = int(input("[?] Select Module : "))
    except:
        print("[!] Only number")
    if id == 1:
        data = caesar(shellcode, mode)
    elif id == 2:
        data = xor(shellcode, mode)
    elif id == 3:
        shellcode, mode = get_shellcode()
    elif id == 123:
        exit()
    id = 0
    show_shellcode(data, mode)
