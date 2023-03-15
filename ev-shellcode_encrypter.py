#!/usr/bin/python

import random

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



mode_arr = [['Caesar', 1], ['shellcode', 2]]

def get_shellcode():
    print("====================================")
    print("[*] Only allow C# format shellcode")
    print("[*] Input your shellcode until enter \"done\"")
    shellcode = []
    tmp = []
    tmp_hex = []
    while True:
        data = input()
        if data == "done":
            break
        else:
            tmp.append(data)
    for i in tmp:
        tmp_int = []
        if "{" in i:
            i = i.split("{")[1]
        elif "}" in i:
            i = i.split("}")[0]
        tmp_line = i.strip(",").split(",")
        for j in tmp_line:
            tmp_int.append(int(j, 16))
        shellcode.append(tmp_int)
    return shellcode

def caesar(shellcode):
    offset = random.randint(2, 24)
    print("[*] Module : Caesar Encode")
    print("[*] Generate offset " + str(offset))
    encrypt = []
    for i in shellcode:
        encrypt_line = []
        for j in i:
            encrypt_line.append((j + offset) % 256)
        encrypt.append(encrypt_line)
    return encrypt

def show_shellcode(data):
    count = 0
    shellcode = []
    for i in data:
        tmp = []
        hex_data = [hex(x) for x in i]
        full_hex = ['0x' + s[2:].zfill(2) for s in hex_data]
        for j in full_hex:
            count += 1
            tmp.append(j)
        shellcode.append(tmp)
    shellcode[len(shellcode) - 1].append("end")
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

shellcode = get_shellcode()
while True:
    print("{:<10}{:2}".format("Modules", "ID"))
    print("{:<10}{:2}".format("-"*8, "-"*3))
    for i in mode_arr:
      print("{:<10}{:<2}".format(i[0], i[1]))
    try:
        id = int(input("[?] Select Module : "))
    except:
        print("[!] Only number")
    if id == 1:
        data = caesar(shellcode)
    elif id == 2:
        shellcode = get_shellcode()
    id = 0
    show_shellcode(data)
