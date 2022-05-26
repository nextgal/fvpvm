# an example of a file loader in Python
# The scripting loader must define at least two functions: accept_file and load_file
# other optional functions are: save_file, move_segm, ...
#
# see also loader.hpp

from email import header
from xmlrpc.client import boolean
import idaapi
import ida_idp
import idc
import struct
from enum import Enum, unique
from array import array

RomFormatName = "Favorite FVP VM Binary"

# -----------------------------------------------------------------------


@unique
class seekPosition(Enum):
    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2


class hcbReader():
    def __init__(self, li: idaapi.loader_input_t):
        self.file = array("B")
        self.size = li.size()
        self.file.frombytes(li.read(self.size))
        self.pos = 0

    def seek(self, pos: int, mode: seekPosition):
        if(mode == seekPosition.SEEK_SET):
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
        ret = struct.unpack(
            s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret

    def readI32(self):
        s = "<i"
        ret = struct.unpack(
            s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret

    def readX32(self):
        return self.readU32()

    def readI16(self):
        s = "<h"
        ret = struct.unpack(
            s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret

    def readU16(self):
        s = "<H"
        ret = struct.unpack(
            s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret

    def readI8(self):
        s = "<b"
        ret = struct.unpack(
            s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret

    def readU8(self):
        s = "<B"
        ret = struct.unpack(
            s, self.file[self.pos:self.pos+struct.calcsize(s)])[0]
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret

    def readI8I8(self):
        s = "<ii"
        ret = struct.unpack(s, self.file[self.pos:self.pos+struct.calcsize(s)])
        self.seek(struct.calcsize(s), seekPosition.SEEK_CUR)
        return ret

    def readString(self, size=0) -> str:
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
            for i in range(0, size + 1):
                char = self.readU8()
                if(char == 0x00):
                    break
                else:
                    ret.append(char)
        return ret.decode(encoding="shift-jis")

    def getRAWArray(self):
        return self.file


def accept_file(li: idaapi.loader_input_t, filename: str):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param filename: name of the file, if it is an archive member name then the actual file doesn't exist
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # our works
    if(li.size() >= 10000000):    # 10M
        return 0
    hcb = hcbReader(li)
    headerOffset = hcb.readU32()
    try:
        hcb.seek(headerOffset, seekPosition.SEEK_SET)
    except Exception:
        return 0
    hcbEntryPoint = hcb.readU32()
    count1 = hcb.readU16()
    count2 = hcb.readU16()
    resMode = hcb.readI16()
    titleLen = hcb.readU8()
    gameTitle = hcb.readString(titleLen)

    # check signature
    return {'format': RomFormatName, 'processor': 'fvp_vm_proc'}

    # unrecognized format
    return 0

# -----------------------------------------------------------------------


def load_file(li: idaapi.loader_input_t, neflags: int, format: str) -> boolean:
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    if format == RomFormatName:
        proc = {'format': RomFormatName, 'processor': 'fvp_vm_proc'}
        idaapi.set_processor_type(proc["processor"], ida_idp.SETPROC_LOADER)

        if(li.size() >= 10000000):    # 10M
            return False

        hcb = hcbReader(li)
        headerOffset = hcb.readU32()
        try:
            hcb.seek(headerOffset, seekPosition.SEEK_SET)
        except Exception:
            return 0
        hcbEntryPoint = hcb.readU32()
        count1 = hcb.readU16()
        count2 = hcb.readU16()
        resMode = hcb.readI16()
        titleLen = hcb.readU8()
        gameTitle = hcb.readString(titleLen)

        """
        3 segements:
            - script
            - hcbinfo
            - imptable
        """
        # copy bytes to the database
        li.file2base(0, 0, li.size(), True)

        hcbHeaderEndOffset = headerOffset+(4+2+2+2+1+titleLen)
        idaapi.add_segm(0, 0, headerOffset, ".script", None)   # script
        idaapi.add_segm(0, headerOffset, hcbHeaderEndOffset,
                        ".hcbinfo", "CONST")   # hcbinfo
        idaapi.add_segm(0, hcbHeaderEndOffset, li.size(),
                        ".imptable", "CONST")  # imptable

        idaapi.add_entry(0, hcbEntryPoint, "entrypoint", 1)
        return True

    idc.warning("Unknown format name: '%s'" % format)
    return 0
