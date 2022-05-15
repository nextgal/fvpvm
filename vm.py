# a FVP VM


import struct
import sys
import os
from enum import Enum
from array import array

class seekPosition(Enum):
    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2

class hcbReader():
    def __init__(self,filename : str):
        self.file = array("B")
        self.size = os.path.getsize(filename)
        with open(filename,"rb") as f:
            self.file.fromfile(f,self.size)
        self.pos = 0
    def seek(self,pos:int,mode:seekPosition):
        if(mode ==seekPosition.SEEK_SET):
            self.pos = pos
        if(mode == seekPosition.SEEK_CUR):
            self.pos += pos
        if(mode == seekPosition.SEEK_END):
            self.pos = self.size = pos
        return self.pos
    def tell(self):
        return self.pos
    def readU32(self):
        s = "<I"
        ret =  struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret
    def readI32(self):
        s = "<i"
        ret =  struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret
    def readX32(self):
        return self.readU32()
    def readI16(self):
        s = "<h"
        ret =  struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret
    def readU16(self):
        s = "<H"
        ret =  struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret
    def readI8(self):
        s = "<b"
        ret =  struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret
    def readU8(self):
        s = "<B"
        ret =  struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret
    def readI8I8(self):
        s = "<ii"
        ret = struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret
    def readString(self,size=0) -> str:
        # read a C-style string
        ret = bytearray()
        if(size == 0):
            while(True):
                char = self.readU8()
                if(char == 0x00):
                    break
                else:
                    ret.append(char)
        else:
            for i in range(0,size + 1):
                char = self.readU8()
                if(char == 0x00):
                    break
                else:
                    ret.append(char)
        return ret.decode(encoding="shift-jis")

    def getRAWArray(self):
        return self.file
    
class vmVarType(Enum):
    T_TRUE = 1,
    T_FALSE = 2,
    T_INT = 3,
    T_FLOAT = 4,
    T_STRING = 5,
    T_RET = 6,
    T_UNDEF = 7     # FVP 自然可没有这个，这个仅用于构造类

class vmOPArg(Enum):
    ARG_NULL = 0,
    ARG_X32 = 1,
    ARG_INT32 = 2,
    ARG_INT16 = 3,
    ARG_INT8 = 4,
    ARG_INT8INT8 = 5,
    ARG_STRING = 6,
    ARG_UNDEF = 7       # 同上

class vmOPCode(Enum):
    OP_NOP = 0x0
    OP_INITSTACK = 0x1
    OP_CALL = 0x02
    OP_SYSCALL = 0x03
    OP_RET = 0x04
    OP_RET2 = 0x05
    OP_JMP = 0x06
    OP_JMPCOND = 0x07
    OP_PUSHTRUE = 0x08
    OP_PUSHFALSE = 0x09
    OP_PUSHINT32 = 0x0a
    OP_PUSHINT16 = 0x0b
    OP_PUSHINT8 = 0x0c
    OP_PUSHFLOAT32 = 0x0d
    OP_PUSHSTRING = 0x0e
    OP_PUSHGLOBAL = 0x0f
    OP_PUSHSTACK = 0x10
    OP_UNK11 = 0x11
    OP_UNK12 = 0x12
    OP_PUSHTOP = 0x13
    OP_PUSHTEMP = 0x14
    OP_POPGLOBAL = 0x15
    OP_COPYSTACK = 0x16
    OP_UNK17 = 0x17
    OP_UNK18 = 0x18
    OP_NEG = 0x19
    OP_ADD = 0x1a
    OP_SUB = 0x1b
    OP_MUL = 0x1c
    OP_DIV = 0x1d
    OP_MOD = 0x1e
    OP_TEST = 0x1f
    OP_LEGEND = 0x20
    OP_LOGOR = 0x21
    OP_EQ = 0x22
    OP_NEQ = 0x23
    OP_QT = 0x24
    OP_LE = 0x25
    OP_LT = 0x26
    OP_GE = 0x27

class vmOPDef():
    def __init__(self):
        self.opcode = vmVarType.T_UNDEF
        self.name = "none"
        self.params = vmOPArg.ARG_UNDEF


class vmStackEntry():
    def __init__(Stype: vmVarType, Sdata: int = 0):
        self.type = Stype
        self.data = Sdata


class vmStackFrame():
    def __init__(OrigSP: int, RetP: int):
        self.sp = OrigSP
        self.rp = RetP

class vmContext():
    def __init__(self):
        self.hcbBuf = bytearray()
        self.ip = 0    # instruction ptr
        self.sp = 0    # stack position / ptr
        self.frameNum = 0   # stack frame?
        self.status = 0
        self.qScanState = 0
        self.stack = vmStackEntry[16]
        self.stackFrame = vmStackFrame[3]


class vm(vmContext):
    def __init__(self,filename):
        self.byteCode = hcbReader(filename)
        self.headerOffset = self.byteCode.readU32()
        self.byteCode.seek(self.headerOffset, seekPosition.SEEK_SET)
        self.hcbEntrypoint = self.byteCode.readU32()
        self.count1 = self.byteCode.readU16()
        self.count2 = self.byteCode.readU16()
        self.resMode = self.byteCode.readI16()
        self.titleLen = self.byteCode.readU8()
        self.gameTitle = self.byteCode.readString(self.titleLen)

        self.ip = self.hcbEntrypoint
        self.byteCode.seek(self.ip, seekPosition.SEEK_SET)
    def readInstruction(self):
        opcode = self.byteCode.readU8()
        print("Opcode: 0x{:x} {}".format(opcode,vmOPCode(opcode).name))
        return vmOPCode(opcode)
    def runVM(self):
        while(True):
            op = self.readInstruction()
            if(op == vmOPCode.OP_NOP):
                pass
            elif(op == vmOPCode.OP_INITSTACK):
                arg1 = self.byteCode.readU8()
                arg2 = self.byteCode.readU8()
                pass
            elif(op == vmOPCode.OP_CALL):
                arg1 = self.byteCode.readU32()
                pass
            elif(op == vmOPCode.OP_SYSCALL):
                arg1 = self.byteCode.readI16()
                pass
            elif(op == vmOPCode.OP_RET):
                pass
            elif(op == vmOPCode.OP_RET2):
                pass
            elif(op == vmOPCode.OP_JMP):
                arg1 = self.byteCode.readX32()
                pass
            elif(op == vmOPCode.OP_JMPCOND):
                arg1 = self.byteCode.readX32()
                pass
            elif(op == vmOPCode.OP_PUSHTRUE):
                pass
            elif(op == vmOPCode.OP_PUSHFALSE):
                pass
            elif(op == vmOPCode.OP_PUSHINT32):
                arg1 = self.byteCode.readI32()
                pass
            elif(op == vmOPCode.OP_PUSHINT16):
                arg1 = self.byteCode.readI16()
                pass
            elif(op == vmOPCode.OP_PUSHINT8):
                arg1 = self.byteCode.readI8()
                pass
            elif(op == vmOPCode.OP_PUSHFLOAT32):
                arg1 = self.byteCode.readX32()
                pass
            elif(op == vmOPCode.OP_PUSHSTRING):
                # wip
                pass
            elif(op == vmOPCode.OP_PUSHGLOBAL):
                arg1 = self.byteCode.readI16()
                pass
            elif(op == vmOPCode.OP_PUSHSTACK):
                arg1 = self.byteCode.readI8()
                pass
            elif(op == vmOPCode.OP_UNK11):
                arg1 = self.byteCode.readI16()
                pass
            elif(op == vmOPCode.OP_UNK12):
                arg1 = self.byteCode.readI8()
                pass
            elif(op == vmOPCode.OP_PUSHTOP):
                pass
            elif(op == vmOPCode.OP_PUSHTEMP):
                pass
            elif(op == vmOPCode.OP_POPGLOBAL):
                arg1 = self.byteCode.readI16()
                pass
            elif(op == vmOPCode.OP_COPYSTACK):
                arg1 = self.byteCode.readI8()
                pass
            elif(op == vmOPCode.OP_UNK17):
                arg1 = self.byteCode.readI16()
                pass
            elif(op == vmOPCode.OP_UNK18):
                arg1 = self.byteCode.readI8()
                pass
            elif(op == vmOPCode.OP_NEG):
                pass
            elif(op == vmOPCode.OP_ADD):
                pass
            elif(op == vmOPCode.OP_SUB):
                pass
            elif(op == vmOPCode.OP_MUL):
                pass
            elif(op == vmOPCode.OP_DIV):
                pass
            elif(op == vmOPCode.OP_MOD):
                pass
            elif(op == vmOPCode.OP_TEST):
                pass
            elif(op == vmOPCode.OP_LEGEND):
                pass
            elif(op == vmOPCode.OP_LOGOR):
                pass
            elif(op == vmOPCode.OP_EQ):
                pass
            elif(op == vmOPCode.OP_NEQ):
                pass
            elif(op == vmOPCode.OP_QT):
                pass
            elif(op == vmOPCode.OP_LE):
                pass
            elif(op == vmOPCode.OP_LT):
                pass
            elif(op == vmOPCode.OP_GE):
                pass
        pass


fvm = vm(sys.argv[1])

print("HCB for FVP Game title: {}".format(fvm.gameTitle))

fvm.runVM()