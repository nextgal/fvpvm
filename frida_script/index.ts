
const enum vmOPCode {
    OP_NOP = 0x00,
    OP_INITSTACK,
    OP_CALL,
    OP_SYSCALL,
    OP_RET,
    OP_RET2,
    OP_JMP,
    OP_JZ,
    OP_PUSHTRUE,
    OP_PUSHFALSE,
    OP_PUSTI32,
    OP_PUSHI16,
    OP_PUSHI8,
    OP_PUSHF32,
    OP_PUSHSTRING,
    OP_PUSHGLOBAL,
    // wrong HERE
    OP_PUSHSTACK,
    OP_UNK11,
    OP_UNK12,
    OP_PUSHTOP,
    OP_PUSHTEMP,
    OP_POPGLOBAL,
    OP_COPYSTACK,
    OP_UNK17,
    OP_UNK18,
    OP_NEG,
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_TEST,
    OP_LEGEND,
    OP_LOGOR,
    OP_EQ,
    OP_NEQ,
    OP_QT,
    OP_LE,
    OP_LT,
    OP_QE
}
var lpFVPGlobalInstance: NativePointer;
var lpFVPVM: NativePointer;
var lpHcbFile: NativePointer;
var lpHcbStackArray: NativePointer;
var bRunOnce: boolean;
/* 
Binary-specific offsets
*/
var OpCodeFuncAddr = [
    new NativePointer(0x41A550),    // 0 / NOP
    new NativePointer(0x445890),    // 1 / INITSTACK
    new NativePointer(0x4458C0),    // 2 / CALL
    new NativePointer(0x445940),    // 3 / SYSCALL
    new NativePointer(0x4448E0),    // 4 / RET
    new NativePointer(0x444900),    // 5 / RET2
    new NativePointer(0x445A10),    // 6 / JMP
    new NativePointer(0x445A30),    // 7 / JZ
    new NativePointer(0x444940),    // 8 / PUSHTRUE
    new NativePointer(0x444960),    // 9 / PUSHFALSE
    new NativePointer(0x445A70),    // A / PUSHI32
    new NativePointer(0x445AA0),    // B / PUSHI16
    new NativePointer(0x445AE0),    // C / PUSHI8
    new NativePointer(0x445B10),    // D / PUSHF32
    new NativePointer(0x445B50),    // E / PUSHSTR
    new NativePointer(0x445B90),    // F / PUSHGLOBAL
    new NativePointer(0x445C20),    // 10 / PUSHSTACK
    new NativePointer(0x445CB0),    // 11 / UNK11
    new NativePointer(0x445D30),    // 12 / UNK12
    new NativePointer(0x444980),    // 13 / PUSHTOP
    new NativePointer(0x4449F0),    // 14 / PUSHTEMP
    new NativePointer(0x445DB0),    // 15 / POPGLOBAL
    new NativePointer(0x445E00),    // 16 / COPYSTACK
    new NativePointer(0x446280),    // 17 / UNK17
    new NativePointer(0x446330),    // 18 / UNK18
    new NativePointer(0x444A20),    // 19 / NEG
    new NativePointer(0x444A60),    // 1a / ADD
    new NativePointer(0x444C50),    // 1b / SUB
    new NativePointer(0x444CE0),    // 1c / MUL
    new NativePointer(0x444D70),    // 1d / DIV
    new NativePointer(0x444DF0),    // 1e / MOD
    new NativePointer(0x444E40),    // 1f / TEST
    new NativePointer(0x444E90),    // 20 / LEGEND
    new NativePointer(0x444ED0),    // 21 / LOGOR
    new NativePointer(0x444F10),    // 22 / EQ
    new NativePointer(0x445020),    // 23 / NEQ
    new NativePointer(0x445060),    // 24 / QT
    new NativePointer(0x445180),    // 25 / LE
    new NativePointer(0x4451C0),    // 26 / LT
    new NativePointer(0x4452E0)     // 27 / QE
]
const klpFVPGLobalInstanceAddr = 0x00481368;
const klpFVPProjectNameOffset = 0x6a7e68;
const klpFVPVMOffset = 0x45c;

function sleep(time: number) {
    return new Promise((resolve) => setTimeout(resolve, time));
}

function HookFVPOpCode() {
    var lpfuncAddr = Module.findBaseAddress("Sakura.exe")

    // FVP VM Registers
    console.log("Address of FVP is: " + lpfuncAddr)
    console.log("Hook FVP...")
    lpFVPGlobalInstance = new NativePointer(new NativePointer(klpFVPGLobalInstanceAddr).readPointer())
    lpFVPVM = new NativePointer(lpFVPGlobalInstance.add(klpFVPVMOffset))
    console.log(`lpFVPVM: ${lpFVPVM}`)
    console.log("FVP Project name: ", lpFVPGlobalInstance.add(klpFVPProjectNameOffset).readPointer().readCString())

    // we can't attach OP_NOP

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_INITSTACK], {
        onEnter: function (args) {
            printSOF()
            // first opCode, BTW get the addr of stack
            lpHcbStackArray = lpFVPVM.add(0x8).readPointer()
            // debug
            /*                 let eip = new NativePointer(lpFVPVM.add(0x81c))
                            let esp = new NativePointer(eip.add(4)).readU32()
                            let ma = lpFVPVM.add(0x8).add(esp * 8).readByteArray(0x40)
                            if (ma) {
                                console.log(hexdump(ma, {
                                    header: true,
                                    ansi: true
                                }))
                            }
                         */
            console.log("OP_INITSTACK");
            PrintFVPRegisters();
            PrintFVPStack();; console.log("--");
        },
        onLeave: function (args) {
            PrintFVPRegisters();
            PrintFVPStack();
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_CALL], {
        onEnter: function (args) {
            printEOF()
            console.log("OP_CALL");
            PrintFVPRegisters();
            PrintFVPStack();; console.log("--");
        },
        onLeave: function (args) {
            PrintFVPRegisters();
            PrintFVPStack();
            console.warn("CALLS a function!")
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_SYSCALL], {
        onEnter: function (args) {
            printSOF()
            console.log("OP_SYSCALL");
            PrintFVPRegisters();
            PrintFVPStack(); console.log("--");
        },
        onLeave: function (args) {
            console.warn("SYSCALL!")
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_RET], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_RET")
            PrintFVPRegisters()
            PrintFVPStack()
            console.warn("RETURN!"); console.log("--");
        }
        , onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_RET2], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_RET2")
            PrintFVPRegisters()
            PrintFVPStack()
            console.warn("RETURN!"); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_JMP], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_JMP")
            PrintFVPRegisters()
            PrintFVPStack()
            console.warn("JUMP!"); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_JZ], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_JZ")
            PrintFVPRegisters()
            PrintFVPStack()
            console.warn("JZ!"); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHTRUE], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHTRUE")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHFALSE], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHFALSE")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSTI32], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHINT32")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHI16], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHINT16")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHI8], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHINT8")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHF32], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHF32")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHSTRING], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHSTRING")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })
    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHGLOBAL], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHGLOBAL")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHSTACK], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHSTACK")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_UNK11], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_UNK11")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_UNK12], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_UNK12")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHTOP], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHTOP")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_PUSHTEMP], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_PUSHTEMP")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_POPGLOBAL], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_POPGLOBAL")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_COPYSTACK], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_COPYSTACK")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_UNK17], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_UNK17")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_UNK18], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_UNK18")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_NEG], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_NEG")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_ADD], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_ADD")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_SUB], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_SUB")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_MUL], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_MUL")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_DIV], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_DIV")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_MOD], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_MOD")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_TEST], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_TEST")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_LEGEND], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_LEGEND")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_LOGOR], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_LOGOR")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_EQ], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_EQ")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_NEQ], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_NEQ")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_QT], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_QT")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_LE], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_LE")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })

    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_LT], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_LT")
            PrintFVPRegisters()
            PrintFVPStack(); console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })
    Interceptor.attach(OpCodeFuncAddr[vmOPCode.OP_QE], {
        onEnter: function (args) {
            printSOF();
            console.log("OP_QE")
            PrintFVPRegisters()
            PrintFVPStack()
                ; console.log("--");
        }, onLeave: function (args) {
            PrintFVPRegisters()
            PrintFVPStack()
            printEOF()
        }
    })


    // for get address of FVPVM object
    Interceptor.attach(new NativePointer(0x00445440), {
        onEnter: function (args) {
            // fuck FRIDA
            // because FRIDA don't let us to read platform-specific registers directly
            // so you can't use `let ecx = this.context.ecx`
            let full_cxt = JSON.parse(JSON.stringify(this.context))
            let ecx = full_cxt.ecx

            lpFVPVM = new NativePointer(ecx)
            Interceptor.revert(new NativePointer(0x00445440));
        }
    })

    console.log("Done!")
    // get hcb info
}

function PrintFVPRegisters() {
    let eip = new NativePointer(lpFVPVM.add(0x81c))
    let esp = new NativePointer(eip.add(4))
    let ebp = new NativePointer(esp.add(8))

    let eip_v: string = eip.readU32().toString(16)
    let esp_v: string = esp.readU32().toString(16)
    let ebp_v: string = ebp.readU32().toString(16)
    console.log(`IP: 0x${eip_v} SP: 0x${esp_v} BP: 0x${ebp_v}`)
}

function PrintFVPStack() {
    let esp = new NativePointer(lpFVPVM.add(0x820)).readU32()   // stack depth

    let lpStackButtom = lpFVPVM.add(0x8)    // little
    let lpStackTop = lpStackButtom.add(esp * 8)  // big

    console.log(`sptr: 0x${lpStackButtom.toString(16)} 0x${lpStackTop.toString(16)}`)     // l / b

    let se = lpStackButtom.readByteArray(esp * 8 + 8)
    if (se) {
        console.log(hexdump(se, { header: true }))
    }

    let ptr = lpStackButtom
    while (ptr <= lpStackTop) {
        let ptr2 = ptr

        // read it!
        /**
            struct FVPStackEntry
            {
            char type;
            char unk;
            __int16 stackBase;
            int value;
            };
         */
        let type_ = ptr2.readU8()
        ptr2 = ptr2.add(1)  // move
        let unk = ptr2.readU8()
        ptr2 = ptr2.add(1)  // still move
        let sbase = ptr2.readS16()
        ptr2 = ptr2.add(2)  // keeps moing
        let value = ptr2.readS32()  // ends, and no moving...

        // pretty 
        /* 
            T_TRUE = 1,
            T_FALSE = 2,
            T_INT = 3,
            T_FLOAT = 4,
            T_STRING = 5,
            T_RET = 6,
        */

        let type_str = ""
        let actualVal: number | string | boolean = ""
        // 推导值
        switch (type_) {
            case 0:
                type_str = "T_TRUE"
                actualVal = true
                break;
            case 1:
                type_str = "T_FALSE"
                actualVal = false
                break;
            case 2:
                type_str = "T_INT"
                actualVal = ptr2.readS32().toString(16)
                break;
            case 4:
                type_str = "T_FLOAT"
                actualVal = ptr2.readFloat().toString(16)
                break;
            case 5:
                type_str = "T_STRING"
                break;
            case 6:
                type_str = "T_RET"
                break;
            default:
                type_str = "unk"
                break;
        }
        // print
        console.log(`stack entry: type: ${type_str} unk1: ${unk} sbase: ${sbase} value: ${actualVal} / ${value}`)
        // next one
        ptr = ptr.add(8)
    }
}

function printSOF() {
    console.log("--- START OF INST ---")
}

function printEOF() {
    console.log("--- END OF INST ---")
}

console.log("Frida version: ", Frida.version)
bRunOnce = true;
// we want hook after FVPVM inited.
Interceptor.attach(new NativePointer(0x00442640), {   // after FVPVM::FVPVM
    onEnter: function (args) {
        console.log("FVP Visual Machine loaded,started hooking!");
        HookFVPOpCode();
        Interceptor.flush()

        // once
        Interceptor.revert(new NativePointer(0x00442640));
    }
})