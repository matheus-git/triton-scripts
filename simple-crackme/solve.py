from triton import *
import lief
import os
import sys

TARGET = os.path.join(os.path.dirname(__file__), 'simple-crackme.exe')

START_ADDR  = 0x1081
CHECK_ADDR  = 0x10C8

RSP = 0x7ffffff0
BUFFER_ADDR = RSP + 0x20
BUFFER_SIZE = 8
PASSWORD = b"password"

def loadBinary(ctx, binary):
    for sec in binary.sections:
        ctx.setConcreteMemoryAreaValue(
            sec.virtual_address,
            list(sec.content)
        )
        print(f"[+] Loading"
              f" {hex(sec.virtual_address)} - {hex(sec.virtual_address + sec.virtual_size)}"
              f" {sec.name}")
    print("-------------------")

def setup(ctx):
    ctx.setConcreteRegisterValue(ctx.registers.rsp, RSP)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, RSP)

    addr = BUFFER_ADDR
    for i in range(BUFFER_SIZE):
        ctx.setConcreteMemoryValue(addr, 0x41)
        sym = ctx.symbolizeMemory(MemoryAccess(addr, CPUSIZE.BYTE))
        sym.setAlias(f"input_{i}")
        addr += 1

    ctx.taintMemory(BUFFER_ADDR)

def solve(ctx):
    result = ""
    for k, v in enumerate(PASSWORD):
        input = ctx.getSymbolicMemory(BUFFER_ADDR+k).getAst()
        model = ctx.getModel(input == v)
        value = next(iter(model.values())).getValue()
        result += chr(value)    
    print("-------------------")
    print("Password: %s" % result)

def run(ctx, pc):
    while pc <= 0x211c:
        inst = Instruction(pc, ctx.getConcreteMemoryAreaValue(pc, 15))
        ctx.processing(inst)

        if inst.isTainted():
            print("[tainted] %s" % inst.getDisassembly())
        
        if inst.getAddress() == CHECK_ADDR:
            solve(ctx)
            break

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)

def main():
    ctx = TritonContext(ARCH.X86_64)

    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.SMT)

    binary = lief.parse(TARGET)
    loadBinary(ctx, binary)

    setup(ctx)
    run(ctx, START_ADDR)

if __name__ == "__main__":
    main()

