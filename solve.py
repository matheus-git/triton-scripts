from triton import TritonContext, ARCH, Instruction, MODE, MemoryAccess, CPUSIZE, AST_REPRESENTATION

CODE = bytes.fromhex(
    "4C8D4C242033C00F1F4000660F1F8400000000008BC8BAEFBEADDE83E103FFC0C1E103D3EA4432C283F80472E745880149FFC1450FB6014584C075C9488D1501220000488D4C2420"
)

BASE = 0x401000

ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setMode(MODE.ALIGNED_MEMORY, True)
ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

ctx.setConcreteMemoryAreaValue(BASE, CODE)

RSP = 0x7ffffff0
ctx.setConcreteRegisterValue(ctx.registers.rsp, RSP)
ctx.setConcreteRegisterValue(ctx.registers.rbp, RSP)

buffer_addr = RSP + 0x20
BUFFER_SIZE = 8

addr = buffer_addr
for i in range(BUFFER_SIZE):
    ctx.setConcreteMemoryValue(addr, 0x41)
    ctx.symbolizeMemory(MemoryAccess(addr, CPUSIZE.BYTE))
    addr = addr + 1

ctx.taintMemory(buffer_addr+1)

ip = BASE
end = BASE + len(CODE)

final_xor = None

while BASE <= ip < end:
    inst = Instruction()
    inst.setAddress(ip)
    inst.setOpcode(ctx.getConcreteMemoryAreaValue(ip, 15))
    ctx.processing(inst)

    if inst.isTainted() and inst.getDisassembly().startswith("xor"):
        print('[tainted] %s' %(str(inst)))
        dl_value = ctx.getConcreteRegisterValue(ctx.registers.dl)
        if final_xor == None:
            final_xor = dl_value
        else:
            final_xor = final_xor ^ dl_value

    ip = ctx.getConcreteRegisterValue(ctx.registers.rip)

print(hex(final_xor))
'''
[tainted] 0x401025: xor r8b, dl
[tainted] 0x401025: xor r8b, dl
[tainted] 0x401025: xor r8b, dl
[tainted] 0x401025: xor r8b, dl
0x22
'''
