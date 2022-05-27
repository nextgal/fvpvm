# FVP VM Specs

FVP 的虚拟机是基于栈的虚拟机，主要由以下部分完成：

- 3个寄存器
    - `IP` 存储下一条要执行指令的地址
    - `SP` 栈指针
    - `BP` 栈基指针
- 深度为 256 的栈
- 一个临时栈区域（深度为1）
- 全局变量存储

## VM Stack Entry Types
被

- 栈条目
- 临时栈条目
- 全局变量

所使用。
```
enum StackEntryType {
    T_FALSE = 0,
    T_TRUE = 1,
    T_INT = 2,
    T_FLOAT = 3,
    T_STRING = 4,
    T_RET = 5
}
```
## VM Instructions spec

FVP 的虚拟机所有指令均为定长（1字节）

### OP_NOP (0x00)
- 机器码：`0x00`
- 操作数：无
- 作用：占位

### OP_INITSTACK (0x01)
- 机器码：`0x01`
- 操作数：
    - `arg1` 1bytes
    - `arg2` 1bytes
- 作用：
    - 覆盖 `sp` 处的栈条目为（类型为arg1，unk为arg2）
    - push `arg2` 个栈条目（类型为0x00 (，值为true) ）

### OP_CALL (0x02)
- 机器码：`0x02`
- 操作数：
    - `arg1` 4bytes
- 作用：
    - 覆盖 `sp` 处的栈条目为（stackBase=`{sp}`,值为`${ep}`+4）
    - 修改 `ip` 为 `arg1`

### OP_SYSCALL (0x03)
- 机器码：`0x03`
- 操作数：
    - `arg1` 2bytes
- 作用：
    - 呼叫 `arg1` 号系统调用

### OP_RET (0x04)
- 机器码：`0x04`
- 操作数：无
- 作用：
    - 返回到
### OP_RET2 (0x05)
- 机器码：`0x05`
- 操作数：无
- 作用：
    - 返回到
### OP_JMP (0x06)
- 机器码：`0x06`
- 操作数：
    - `arg1` 4bytes
- 操作：无条件跳转
### OP_JMPCOND (0x07)
- 机器码：`0x07`
- 操作数：
    - `arg1` 4bytes
- 操作：
    - 栈顶为`0`时跳转
### OP_PUSHTRUE (0x08)
- 机器码：`0x08`
- 操作数：无
- 操作：向堆栈中压入一个 `true` / `T_TRUE` / 0
### OP_PUSHFALSE (0x09)
- 机器码：`0x09`
- 操作数：无
- 操作：向堆栈中压入一个 `false` / `T_FALSE` / 1
### OP_PUSHINT32 (0x0a)
- 机器码：`0x0a`
- 操作数：
    - `arg1` 4bytes
- 操作：向堆栈中压入一个整数 `arg1`
### OP_PUSHINT16 (0x0b)
- 机器码：`0x0b`
- 操作数：
    - `arg1` 2bytes
- 操作：向堆栈中压入一个整数 `arg1`
### OP_PUSHINT8 (0x0c)
- 机器码：`0x0c`
- 操作数：
    - `arg1` 1bytes
- 操作：向堆栈中压入一个整数 `arg1`
### OP_PUSHF32 (0x0d)
- 机器码：`0x0d`
- 操作数：
    - `arg1` 4bytes
- 操作：向堆栈中压入一个浮点数 `arg1`
### OP_PUSHSTRING (0x0e)
- 机器码：`0x0e`
- 操作数：
    - `arg1` 4bytes
- 操作：向堆栈中压入一个指向字符串的指针 `arg1`
### OP_PUSHGLOBAL (0x0f)
- 机器码：`0x0f`
- 操作数：
    - `arg1` 2bytes
- 操作：读取全局变量 `arg1` 的值并将值压入堆栈
- **对于不存在的全局变量**：返回 `false`
### OP_PUSHSTACK (0x10)
- 机器码：`0x10`
- 操作数：
    - `arg1` 1bytes
- 操作：将 `sp + arg1` 处的栈内容提出来压入堆栈
### OP_UNK11 (0x11)
- 机器码：`0x11`
- 操作数：
    - `arg1` 2bytes
- 操作：未知
### OP_UNK12 (0x12)
- 机器码：`0x12`
- 操作数：
    - `arg1` 1bytes
- 操作：未知
### OP_PUSHTOP (0x13)
- 机器码：`0x13`
- 操作：将 `sp` 处的栈内容再次压入堆栈
### OP_PUSHTEMP (0x14)
- 机器码：`0x14`
- 操作：将临时堆栈的内容压入（主）堆栈，并清零临时堆栈
### OP_POPGLOBAL (0x15)
- 机器码：`0x15`
- 操作数：
        - `arg1` 2bytes
- 操作：将全局变量 `arg1` 设置为 `sp` 处的堆栈内容，*之后 pop 出该 entry*
### OP_COPYSTACK (0x16)
- 机器码：`0x16`
- 操作数：
    - `arg1` 1bytes
- 操作：将 `sp - arg1` 处的栈内容提出来压入堆栈
### OP_UNK17 (0x17)
- 机器码：`0x17`
- 操作数：
    - `arg1` 2bytes
- 操作：未知
### OP_UNK18 (0x18)
- 机器码：`0x18`
- 操作数：
    - `arg1` 1bytes
- 操作：未知
### OP_NEG (0x19)
- 机器码：`0x19`
- 操作：等价于下面的x86汇编：
```
pop eax
dec eax
push eax
```
### OP_ADD (0x1a)
- 机器码：`0x1a`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret = arg1 + arg2`
    - 压入 `ret`
### OP_SUB (0x1b)
- 机器码：`0x1b`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret = arg1 - arg2`
    - 压入 `ret`
### OP_MUL (0x1c)
- 机器码：`0x1c`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret = arg1 * arg2`
    - 压入 `ret`
### OP_DIV (0x1d)
- 机器码：`0x1d`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret = arg1 / arg2`
    - 压入 `ret`
### OP_MOD (0x1e)
- 机器码：`0x1e`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret = arg1 % arg2`
    - 压入 `ret`
### OP_TEST (0x1f)
- 机器码：`0x1f`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret = arg1 & (1 << arg2) ? 1 : 0`
    - 压入 `ret`
### OP_LEGEND (0x20)
- 机器码：`0x20`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `arg1 = type(arg1);arg2 = type(arg2)`
    - `ret.type = (arg1 && arg2)`
    - 压入 `ret`
### OP_LOGOR (0x21)
- 机器码：`0x21`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `arg1 = type(arg1);arg2 = type(arg2)`
    - `ret.type = (arg1 || arg2)`
    - 压入 `ret`
### OP_EQ (0x22)
- 机器码：`0x22`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret.type = (arg1 == arg2)`
    - 压入 `ret`
### OP_NEQ (0x23)
- 机器码：`0x23`
- 操作：
    - 弹出参数 `arg1`,`arg2`
    - `ret.type = (arg1 != arg2)`
    - 压入 `ret`
### OP_QT (0x24)
- 机器码：`0x24`
### OP_LE (0x25)
- 机器码：`0x25`
### OP_LT (0x26)
- 机器码：`0x26`
### OP_GE (0x27)
- 机器码：`0x27`