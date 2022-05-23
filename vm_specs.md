# FVP VM Specs

FVP 的虚拟机是基于栈的虚拟机，主要由以下部分完成：

- 3个寄存器
    - `IP` 存储下一条要执行指令的地址
    - `SP` 栈指针
    - `BP` 栈基指针
- 深度为 256 的栈
- 一个临时栈区域（深度为1）
- 全局变量存储

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