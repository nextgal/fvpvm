# ----------------------------------------------------------------------
# Processor module template script
# (c) Hex-Rays
from multiprocessing.sharedctypes import Value
from pickletools import uint8
from xmlrpc.client import Boolean, boolean
import idaapi
from idaapi import *
import ida_pro
import idc

# ----------------------------------------------------------------------


class fvp_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    A processor_t instance is, conceptually, both an IDP_Hooks and
    an IDB_Hooks. This means any callback from those two classes
    can be implemented. Below, you'll find a handful of those
    as an example (e.g., ev_out_header(), ev_newfile(), ...)
    Also note that some IDP_Hooks callbacks must be implemented
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 460

    # Processor features
    flag = PR_ASSEMBLE | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['fvp_vm_proc']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['Processor module for FVP VM']

    # register names
    reg_names = [
        # General purpose registers
        "IP",
        "SP",
        "BP",
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(reg_names))
    regs_num = len(reg_names)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    reg_first_sreg = 3  # index of CS
    reg_last_sreg = 4  # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    reg_code_sreg = 3
    reg_data_sreg = 4

    # Array of typical code start sequences (optional)
    codestart = ['\x01']

    # Array of 'return' instruction opcodes (optional)
    retcodes = ['\x04', '\x05']

    # icode of the first instruction
    instruc_start = 0

    instruc = []
    # icode of the last instruction + 1
    instruc_end = 0

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = 4

    # only one assembler is supported
    assembler = {
        # flag
        'flag': ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag': 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # remove if not allowed
        'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    }  # Assembler

    def regname2index(self, regname):
        for idx in range(len(self.reg_names)):
            if regname == self.reg_names[idx]:
                return idx
        return -1

    OPTION_KEY_OPERAND_SEPARATOR = "PROCTEMPLATE_OPERAND_SEPARATOR"
    OPTION_KEY_OPERAND_SPACES = "PROCTEMPLATE_OPERAND_SPACES"

    def initFVPInstructions(self):
        class idef:
            """
            Internal class that describes an instruction by:
            - instruction name
            - instruction decoding routine
            - canonical flags used by IDA
            """

            def __init__(self, name, cf, cmt=None):
                self.name = name
                self.cf = cf
                self.cmt = cmt
        self.itable = {
            0x00: idef(name="NOP", cf=0, cmt="No operation"),
            0x01: idef(name="INIT_STACK", cf=CF_USE2 | OF_NUMBER, cmt="Init function stack"),
            0x02: idef(name="CALL", cf=CF_USE1 | CF_CALL, cmt="Call a function"),
            0x03: idef(name="SYSCALL", cf=CF_USE1 | CF_HLL | OF_NUMBER, cmt="Syscall"),
            0x04: idef(name="RET", cf=CF_STOP, cmt="Return"),
            0x05: idef(name="RET2", cf=CF_STOP, cmt="Return"),
            0x06: idef(name="JMP", cf=CF_USE1 | CF_JUMP, cmt="Jump"),
            0x07: idef(name="JMPCOND", cf=CF_USE1 | CF_JUMP, cmt="Jump Conditionaly"),
            0x08: idef(name="PUSHTRUE", cf=CF_USE1, cmt="Push True"),
            0x09: idef(name="PUSHFALSE", cf=CF_USE1, cmt="Push False"),
            0x0a: idef(name="PUSHI32", cf=CF_USE1 | OF_NUMBER, cmt="Push Integer"),
            0x0b: idef(name="PUSHI16", cf=CF_USE1 | OF_NUMBER, cmt="Push Integer"),
            0x0c: idef(name="PUSHI8", cf=CF_USE1 | OF_NUMBER, cmt="Push Integer"),
            0x0d: idef(name="PUSHF32", cf=CF_USE1 | OF_NUMBER, cmt="Push Float"),
            0x0e: idef(name="PUSHSTRING", cf=CF_USE2, cmt="Push String"),
            0x0f: idef(name="PUSHGLOBAL", cf=CF_USE1, cmt="Push Global Var to stack"),
            0x10: idef(name="PUSHSTACK", cf=CF_USE1, cmt=""),
            0x11: idef(name="UNK11", cf=CF_USE1, cmt="unk"),
            0x12: idef(name="UNK12", cf=CF_USE1, cmt="unk"),
            0x13: idef(name="PUSHTOP", cf=0, cmt="Push stack entry"),
            0x14: idef(name="PUSHTEMP", cf=0, cmt="Push temp stack entry to stack"),
            0x15: idef(name="POPGLOBAL", cf=CF_USE1, cmt="push stack entry to global var"),
            0x16: idef(name="COPYSTACK", cf=CF_USE1, cmt=""),
            0x17: idef(name="UNK17", cf=CF_USE1, cmt="unk"),
            0x18: idef(name="UNK18", cf=CF_USE1, cmt="unk"),
            0x19: idef(name="NEG", cf=0, cmt="dec"),
            0x1a: idef(name="ADD", cf=0, cmt="add"),
            0x1b: idef(name="SUB", cf=0, cmt=""),
            0x1c: idef(name="MUL", cf=0, cmt=""),
            0x1d: idef(name="DIV", cf=0, cmt=""),
            0x1e: idef(name="MOD", cf=0, cmt=""),
            0x1f: idef(name="TEST", cf=0, cmt=""),
            0x20: idef(name="LEGEND", cf=0, cmt=""),
            0x21: idef(name="LOGOR", cf=0, cmt=""),
            0x22: idef(name="EQ", cf=0, cmt=""),
            0x23: idef(name="NEQ", cf=0, cmt="!eq"),
            0x24: idef(name="QT", cf=0, cmt=""),
            0x25: idef(name="LE", cf=0, cmt=""),
            0x26: idef(name="LT", cf=0, cmt=""),
            0x27: idef(name="GE", cf=0, cmt="")
        }

        # Now create an instruction table compatible with IDA processor module requirements

        i = 0
        for x in self.itable.values():
            d = dict(name=x.name, feature=x.cf)
            if x.cmt != None:
                d['cmt'] = x.cmt
            self.instruc.append(d)
            setattr(self, 'itype_' + x.name, i)
            i += 1
    # ----------------------------------------------------------------------

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.operand_separator = ','
        self.operand_spaces = 1
        self.initFVPInstructions()
        self.instruc_end = len(self.instruc)
        self.syscall = []
        self.syscallInited = False

    def asm_out_func_header(self, ctx: idaapi.outctx_t, func_ea):
        """generate function header lines"""
        pass

    def asm_out_func_footer(self, ctx: idaapi.outctx_t, func_ea):
        """generate function footer lines"""
        pass

    def asm_get_type_name(self, flag, ea_or_id):
        """
        Get name of type of item at ea or id.
        (i.e. one of: byte,word,dword,near,far,etc...)
        """
        if is_code(flag):
            pfn = get_func(ea_or_id)
            # return get func name
        elif is_word(flag):
            return "word"
        return ""

    #
    # IDP_Hooks callbacks (the first 4 are mandatory)
    #

    def ev_emu_insn(self, insn: idaapi.insn_t):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        # for strings
        if insn.itype == getattr(self, "itype_"+self.instruc[0x0e]["name"]):
            # PUSHSTR
            idaapi.create_strlit(insn.Op2.addr, insn.Op1.value, STRTYPE_C)
            add_cref(insn.ea, insn.ea + insn.size + insn.Op1.value, fl_F)
            add_dref(insn.ea, insn.ea+2, dr_T | dr_R)
            return True

        if insn.itype & CF_JUMP:  # JMP
            add_cref(insn.ea, insn.Op1.addr, fl_JN)
        if insn.itype & CF_CALL:
            add_cref(insn.ea, insn.Op1.addr, fl_CN)
            add_cref(insn.ea, insn.ea + insn.size, fl_F)
            pass
        if (insn.itype & CF_USE1) or (insn.itype & CF_USE2) or (insn.itype != 2):
            # print("insnsize: {} ip: {}".format(insn.size, insn.ea))
            add_cref(insn.ea, insn.ea + insn.size, fl_F)
        if insn.itype == getattr(self, "itype_"+self.instruc[0x03]["name"]):
            idc.set_cmt(insn.ea, self.syscall[insn.Op1.value]["sym"], False)
            add_dref(insn.ea, self.syscall[insn.Op1.value]["addr"], dr_I)
            pass

        return True

    def ev_out_operand(self, ctx: idaapi.outctx_t, op: idaapi.op_t):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: success
        """
        if op.type == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif op.type == o_imm:
            ctx.out_value(op, OOFW_IMM)
        elif op.type == o_mem:
            ctx.out_name_expr(op, op.addr, BADADDR)
        else:
            return False
        return True

    def ev_out_insn(self, ctx: idaapi.outctx_t) -> None:
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()

        for i in range(0, 2):
            op = ctx.insn[i]
            if op.type == o_void:
                break
            if i > 0:
                ctx.out_symbol(self.operand_separator)
                for _ in range(self.operand_spaces):
                    ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    def ev_ana_insn(self, insn: idaapi.insn_t) -> Boolean:
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """

        if(self.syscallInited != True):
            ep = idaapi.get_dword(0)
            ep += 0x50
            seg: idaapi.segment_t = idaapi.get_segm_by_name(".imptable")
            ptr = seg.start_ea
            syscallSize = idaapi.get_word(ptr)
            ptr += 2
            for i in range(syscallSize):
                idx = i
                type = idaapi.get_byte(ptr)
                ptr += 1
                symlen = idaapi.get_byte(ptr)
                ptr += 1
                addr = ptr
                sym: bytes = idaapi.get_bytes(ptr, symlen - 1, 0)
                symname = sym.decode(encoding="ascii")
                ptr += symlen
                self.syscall.append(
                    {"argsnum": type, "sym": symname, "addr": addr})
                pass
            self.syscallInited = True

        insn.size = 0
        opcode: uint8 = insn.get_next_byte()
        # just LUT
        op = opcode
        if(op == 0x00):  # NOP
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x01):   # INITSTACK
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_byte()
            arg2 = insn.get_next_byte()
            insn.Op1.type = o_imm
            insn.Op2.type = o_imm
            insn.Op1.value = arg1
            insn.Op2.value = arg2
            insn.Op1.dtype = dt_byte
            insn.Op2.dtype = dt_byte
            pass
        elif(op == 0x02):   # CALL
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_dword()
            insn.Op1.type = o_mem
            insn.Op1.addr = arg1
            pass
        elif(op == 0x03):   # SYSCALL
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_word()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_word
            pass
        elif(op == 0x04):   # RET
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x05):   # RET2
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x06):   # JMP
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_dword()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_dword
            pass
        elif(op == 0x07):   # JMPCOND
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_dword()
            # print("0x{:x}".format(arg1))
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_dword
            pass
        elif(op == 0x08):   # PUSHTRUE
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x09):   # PUSHFALSE
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x0a):   # PUSHI32
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_dword()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_dword
            pass
        elif(op == 0x0b):   # PUSHI16
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_word()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_word
            pass
        elif(op == 0x0c):   # PUSHI8
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_byte()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_byte
            pass
        elif(op == 0x0d):   # PUSHF32
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_dword()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_float
            pass
        elif(op == 0x0e):   # PUSHSTRING
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_byte()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_byte
            insn.Op2.type = o_mem
            insn.Op2.addr = insn.ip + 2
            pass
        elif(op == 0x0f):   # PUSHGLOBAL
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_word()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_word
            pass
        elif(op == 0x10):   # PUSHSTACK
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_byte()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_word
            pass
        elif(op == 0x11):   # UNK11
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_word()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_word
            pass
        elif(op == 0x12):   # UNK12
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_byte()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_byte
            pass
        elif(op == 0x13):   # PUSHTOP
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x14):   # PUSHTEMP
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x15):   # POPGLOBAL
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_word()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_word
            pass
        elif(op == 0x16):   # COPYSTACK
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_byte()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_byte
            pass
        elif(op == 0x17):   # UNK17
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_word()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_word
            pass
        elif(op == 0x18):   # UNK18
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            arg1 = insn.get_next_byte()
            insn.Op1.type = o_imm
            insn.Op1.value = arg1
            insn.Op1.dtype = dt_byte
            pass
        elif(op == 0x19):   # NEG
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x1a):   # ADD
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x1b):   # SUB
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x1c):   # MUL
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x1d):   # DIV
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x1e):   # MOD
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x1f):   # TEST
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x20):   # LEGEND
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x21):   # LOGOR
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x22):   # EQ
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x23):   # NEQ
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x24):   # QT
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x25):   # LE
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x26):   # LT
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass
        elif(op == 0x27):   # GE
            ins = self.itable[opcode]
            insn.itype = getattr(self, "itype_"+ins.name)
            pass

        return True

    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    def ev_out_header(self, ctx: idaapi.outctx_t):
        """function to produce start of disassembled text"""
        return 0

    def ev_out_footer(self, ctx: idaapi.outctx_t):
        """function to produce end of disassembled text"""
        return 0

    def ev_out_segstart(self, ctx: idaapi.outctx_t, segment):
        """function to produce start of segment"""
        return 0

    def ev_out_segend(self, ctx: idaapi.outctx_t, segment):
        """function to produce end of segment"""
        return 0

    def ev_out_assumes(self, ctx: idaapi.outctx_t):
        """function to produce assume directives"""
        return 0

    def ev_term(self):
        """called when the processor module is unloading"""
        return 0

    def ev_setup_til(self):
        """Setup default type libraries (called after loading a new file into the database)
        The processor module may load tils, setup memory model and perform other actions required to set up the type system
        """
        return 0

    def ev_newprc(self, nproc, keep_cfg):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        return >=0-ok,<0-prohibit
        """
        return 0

    def ev_newfile(self, filename):
        """A new file is loaded (already)"""
        return 0

    def ev_oldfile(self, filename):
        """An old file is loaded (already)"""
        return 0

    def ev_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
         args:
          filename  - binary file name
          fileoff   - offset in the file
          basepara  - base loading paragraph
          binoff    - loader offset
          nbytes    - number of bytes to load
        """
        return 0

    def ev_undefine(self, ea):
        """
        An item in the database (insn or data) is being deleted
        @param args: ea
        @return: >=0-ok, <0 - the kernel should stop
                 if the return value is not negative:
                     bit0 - ignored
                     bit1 - do not delete srareas at the item end
        """
        return 0

    def ev_endbinary(self, ok):
        """
         After loading a binary file
         args:
          ok - file loaded successfully?
        """
        return 0

    def ev_assemble(self, ea, cs, ip, use32, line):
        """
        Assemble an instruction
         (make sure that PR_ASSEMBLE flag is set in the processor flags)
         (display a warning if an error occurs)
         args:
           ea -  linear address of instruction
           cs -  cs of instruction
           ip -  ip of instruction
           use32 - is 32bit segment?
           line - line to assemble
        returns the opcode string, or None
        """
        return 0

    def ev_out_data(self, ctx, analyze_only):
        """
        Generate text represenation of data items
        This function MAY change the database and create cross-references, etc.
        """
        ctx.out_data(analyze_only)
        return 1

    def ev_cmp_operands(self, op1, op2):
        """
        Compare instruction operands.
        Returns 1-equal, -1-not equal, 0-not implemented
        """
        return 0

    def ev_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
        """
        Set IDP-specific option
        args:
          keyword    - the option name
                       or empty string (check value_type when 0 below)
          value_type - one of
                         IDPOPT_STR  string constant
                         IDPOPT_NUM  number
                         IDPOPT_BIT  zero/one
                         IDPOPT_I64  64bit number
                         0 -> You should display a dialog to configure the processor module
          value   - the actual value
          idb_loaded - true if the ev_oldfile/ev_newfile events have been generated
        Returns:
           1 ok
           0 not implemented
           -1 error
        """
        if keyword == self.OPTION_KEY_OPERAND_SEPARATOR and value_type == ida_idp.IDPOPT_STR:
            self.operand_separator = value
            return 1
        if keyword == self.OPTION_KEY_OPERAND_SPACES and value_type == ida_idp.IDPOPT_NUM:
            self.operand_spaces = value
            return 1
        else:
            return -1

    def ev_gen_map_file(self, nlines, qfile):
        """
        Generate map file. If this function is absent then the kernel will create the map file.
        This function returns number of lines in output file.
        0 - not implemented, 1 - ok, -1 - write error
        """
        import ida_fpro
        qfile = ida_fpro.qfile_t_from_fp(fp)
        lines = ["Line 1\n", "Line 2\n!"]
        ida_pro.int_pointer.frompointer(nlines).assign(len(lines))
        for l in lines:
            qfile.write(l)
        return 1

    def ev_create_func_frame(self, pfn):
        """
        Create a function frame for a newly created function.
        Set up frame size, its attributes etc.
        """
        return 0

    def ev_is_far_jump(self, icode):
        """
        Is indirect far jump or call instruction?
        meaningful only if the processor has 'near' and 'far' reference types
        """
        return 0

    def ev_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return 0

    def ev_out_special_item(self, ctx, segtype):
        """
        Generate text representation of an item in a special segment
        i.e. absolute symbols, externs, communal definitions etc.
        Returns: 1-ok, 0-not implemented
        """
        return 0

    def ev_get_frame_retsize(self, frsize, pfn):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        ida_pro.int_pointer.frompointer(frsize).assign(2)
        return 1

    def ev_is_switch(self, swi, insn):
        """
        Find 'switch' idiom at instruction 'insn'.
        Fills 'swi' structure with information
        """
        return 0

    def ev_is_sp_based(self, mode, insn, op):
        """
        Check whether the operand is relative to stack pointer or frame pointer.
        This function is used to determine how to output a stack variable
        This function may be absent. If it is absent, then all operands
        are sp based by default.
        Define this function only if some stack references use frame pointer
        instead of stack pointer.
        returns flags:
          OP_FP_BASED   operand is FP based
          OP_SP_BASED   operand is SP based
          OP_SP_ADD     operand value is added to the pointer
          OP_SP_SUB     operand value is substracted from the pointer
        """
        ida_pro.int_pointer.frompointer(mode).assign(idaapi.OP_FP_BASED)
        return 1

    def ev_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        return "comment for %d" % insn.itype

    def ev_create_switch_xrefs(self, jumpea, swi):
        """Create xrefs for a custom jump table
           @param jumpea: address of the jump insn
           @param swi: switch information
        """
        return 0

    def ev_calc_step_over(self, target, ip):
        ida_pro.ea_pointer.frompointer(target).assign(idaapi.BADADDR)
        return 1

    def ev_may_be_func(self, insn, state):
        """
        can a function start here?
        the instruction is in 'insn'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        return 0

    def ev_str2reg(self, regname):
        """
        Convert a register name to a register number
          args: regname
          Returns: register number or -1 if not avail
          The register number is the register index in the reg_names array
          Most processor modules do not need to implement this callback
          It is useful only if ph.reg_names[reg] does not provide
          the correct register names
        """
        r = self.regname2index(regname)
        if r < 0:
            return 0
        else:
            return r + 1

    def ev_is_sane_insn(self, insn, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'insn'
        returns: >=0-ok, <0-no, the instruction isn't
        likely to appear in the program
        """
        return -1

    def ev_func_bounds(self, code, func_ea, max_func_end_ea):
        ida_pro.int_pointer.frompointer(code).assign(FIND_FUNC_OK)
        return 1

    def ev_init(self, idp_file):
        return 0

    def ev_out_label(self, ctx, label):
        """
        The kernel is going to generate an instruction label line
        or a function header.
        args:
          ctx - output context
          label - label to output
        If returns value <0, then the kernel should not generate the label
        """
        return 0

    def ev_rename(self, ea, new_name):
        """
        The kernel is going to rename a byte
        args:
          ea -
          new_name -
        If returns value <0, then the kernel should not rename it
        """
        return 0

    def ev_may_show_sreg(self, ea):
        """
        The kernel wants to display the segment registers
        in the messages window.
        args:
          ea
        if this function returns <0
        then the kernel will not show
        the segment registers.
        (assuming that the module have done it)
        """
        return 0

    def ev_coagulate(self, start_ea):
        """
        Try to define some unexplored bytes
        This notification will be called if the
        kernel tried all possibilities and could
        not find anything more useful than to
        convert to array of bytes.
        The module can help the kernel and convert
        the bytes into something more useful.
        args:
          start_ea -
        returns: number of converted bytes
        """
        return 0

    def ev_is_call_insn(self, insn):
        """
        Is the instruction a "call"?
        args
          insn  - instruction
        returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def ev_is_ret_insn(self, insn, strict):
        """
        Is the instruction a "return"?
        insn  - instruction
        strict - 1: report only ret instructions
                 0: include instructions like "leave"
                    which begins the function epilog
        returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def ev_is_alloca_probe(self, ea):
        """
        Does the function at 'ea' behave as __alloca_probe?
        args:
          ea
        returns: 1-yes, 0-false
        """
        return 0

    def ev_gen_src_file_lnnum(self, ctx, filename, lnnum):
        """
        Callback: generate analog of
        #line "file.c" 123
        directive.
        args:
          ctx   - output context
          file  - source file (may be NULL)
          lnnum - line number
        returns: 1-directive has been generated
        """
        return 0

    def ev_is_indirect_jump(self, insn):
        """
        Callback: determine if instruction is an indrect jump
        If CF_JUMP bit cannot describe all jump types
        jumps, please define this callback.
        input: insn structure contains the current instruction
        returns: 0-use CF_JUMP, 1-no, 2-yes
        """
        return 0

    def ev_validate_flirt_func(self, ea, funcname):
        """
        flirt has recognized a library function
        this callback can be used by a plugin or proc module
        to intercept it and validate such a function
        args:
          start_ea
          funcname
        returns: -1-do not create a function,
                  0-function is validated
        """
        return 0

    def ev_set_proc_options(self, options, confidence):
        """
        called if the user specified an option string in the command line:
        -p<processor name>:<options>
        can be used for e.g. setting a processor subtype
        also called if option string is passed to set_processor_type()
        and IDC's set_processor_type()
        args:
          options
          confidence - 0: loader's suggestion,
                       1: user's decision
        returns: <0 - bad option string
        """
        return 0

    def ev_creating_segm(self, s):
        return 0

    def ev_auto_queue_empty(self, atype):
        return 0

    def ev_gen_regvar_def(self, ctx, v):
        return 0

    def ev_is_basic_block_end(self, insn, call_insn_stops_block):
        """
        Is the current instruction end of a basic block?
        This function should be defined for processors
        with delayed jump slots. The current instruction
        is stored in 'insn'
        args:
          call_insn_stops_block
          returns: 0-unknown, -1-no, 1-yes
        """
        return 0

    def ev_moving_segm(self, segment, to, flags):
        """
        May the kernel move the segment?
        returns: 0-yes, <0-the kernel should stop
        """
        return 0

    def ev_segm_moved(self, from_ea, to_ea, size, changed_netdelta):
        """
        A segment is moved
        """
        return 0

    def ev_verify_noreturn(self, pfn):
        """
        The kernel wants to set 'noreturn' flags for a function
        Returns: 0-ok, <0-do not set 'noreturn' flag
        """
        return 0

    def ev_treat_hindering_item(self, hindering_item_ea, new_item_flags, new_item_ea, new_item_length):
        """
        An item hinders creation of another item
        args:
          hindering_item_ea
          new_item_flags
          new_item_ea
          new_item_length
        Returns: 0-no reaction, <0-the kernel may delete the hindering item
        """
        return 0

    def ev_coagulate_dref(self, from_ea, to_ea, may_define, code_ea):
        """
        data reference is being analyzed
        args:
          from_ea, to_ea, may_define, code_ea
        plugin may correct code_ea (e.g. for thumb mode refs, we clear the last bit)
        Returns: new code_ea or -1 - cancel dref analysis
        """
        if False:  # some condition
            ida_pro.ea_pointer.frompointer(code_ea).assign(0x1337)
        return 0

    #
    # IDB_Hooks callbacks
    #

    def savebase(self):
        """The database is being saved. Processor module should save its local data"""
        return 0

    def closebase(self):
        """
        The database will be closed now
        """
        return 0

    def idasgn_loaded(self, short_sig_name):
        """
        FLIRT signature have been loaded for normal processing
        (not for recognition of startup sequences)
        args:
          short_sig_name
        """
        return 0

    def auto_empty(self):
        """
        Info: all analysis queues are empty.
        This callback is called once when the
        initial analysis is finished. If the queue is
        not empty upon the return from this callback,
        it will be called later again
        """
        return 0

    def kernel_config_loaded(self, pass_number):
        """
        This callback is called when ida.cfg is parsed
        """
        return 0

    def auto_empty_finally(self):
        """
        Info: all analysis queues are empty definitively
        """
        return 0

    def determined_main(self, main_ea):
        """
        The main() function has been determined
        """
        return 0

    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        return 0

    def compiler_changed(self, adjust_inf_fields):
        return 0

    def make_code(self, insn):
        """
        An instruction is being created
        args:
          insn
        returns: 0-ok, <0-the kernel should stop
        """
        return 0

    def make_data(self, ea, flags, tid, size):
        """
        A data item is being created
        args:
          ea
          flags
          tid
          size
        returns: 0-ok, <0-the kernel should stop
        """
        return 0

    def notify_verify_sp(self, pfn):
        """
        All function instructions have been analyzed
        Now the processor module can analyze the stack pointer
        for the whole function
        Returns: 0-ok, <0-bad stack pointer
        """
        return 0

    def renamed(self, ea, new_name, is_local_name):
        """
        The kernel has renamed a byte
        args:
          ea
          new_name
          is_local_name
        Returns: nothing. See also the 'rename' event
        """
        return 0

    def set_func_start(self, pfn, new_ea):
        """
        Function chunk start address will be changed
        args:
          pfn
          new_ea
        Returns: 0-ok,<0-do not change
        """
        return 0

    def set_func_end(self, pfn, new_end_ea):
        """
        Function chunk end address will be changed
        args:
          pfn
          new_end_ea
        Returns: 0-ok,<0-do not change
        """
        return 0

    def func_added(self, pfn):
        """
        The kernel has added a function.
        @param pfn: function
        """
        return 0

    def deleting_func(self, pfn):
        """
        The kernel is about to delete a function
        @param func: function
        """
        return 0

    def translate(self, base, offset):
        """
        Translation function for offsets
        Currently used in the offset display functions
        to calculate the referenced address
        Returns: ea_t
        """
        return BADADDR

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t


def PROCESSOR_ENTRY():
    return fvp_processor_t()
