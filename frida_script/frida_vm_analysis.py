# 使用 frida，将 FVP 转换成 real-time 的反汇编器

import sys
from win32process import CreateProcess, ResumeThread, STARTUPINFO
from win32api import MessageBox
from win32con import CREATE_SUSPENDED, MB_ICONINFORMATION, MB_OK
import frida


"""
for *さくら、もゆ。 -as the Night's, Reincarnation-* only
"""
ksFVPImagePath = "Sakura.exe"
ksFVPDataPath = "D:\\Games\\さくら、もゆ。"

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

def fridaStart(sJSCode:str):
    pc = frida.get_local_device()
    fvpPID = -1
    print(pc)
    for process in pc.enumerate_processes():
        if(process.name == ksFVPImagePath):
            print("{}\t(PID: {})".format(process.name,process.pid))
            fvpPID = process.pid
    s = pc.attach(fvpPID)

    # load FRIDA script
    scriptBlock = s.create_script(sJSCode)
    scriptBlock.on('message', on_message)   # register hook for `console.log()`
    scriptBlock.load()  # run
    pass

def main():
    si = STARTUPINFO()
    ret = CreateProcess(
        ksFVPDataPath + "\\" + ksFVPImagePath, None, None, None, False, CREATE_SUSPENDED, None, ksFVPDataPath, si)
    MessageBox(0, "Catch FVP!", "Info", MB_ICONINFORMATION, MB_OK)

    # read JS Code
    with open("frida_script/_agent.js","r") as handle:
        sJSCode = handle.read()
        # do frida thing
        fridaStart(sJSCode)

    ResumeThread(ret[1])
    pass


main()
