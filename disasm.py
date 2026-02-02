from triton import TritonContext, ARCH, Instruction, MODE

CODE = bytes.fromhex(
    "33C00F1F4000660F1F8400000000008BC8BAEFBEADDE83E103FFC0C1E103D3EA4432C283F80472E745880149FFC1450FB6014584C075C9488D1501220000488D4C2420E8B60F0000"
)

BASE = 0x401000

ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setMode(MODE.ALIGNED_MEMORY, True)

ctx.setConcreteMemoryAreaValue(BASE, CODE)

ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7ffffff0)
ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x7ffffff0)

ip = BASE
end = BASE + len(CODE)

while BASE <= ip < end:
    inst = Instruction()
    inst.setAddress(ip)
    inst.setOpcode(ctx.getConcreteMemoryAreaValue(ip, 15))
    ctx.processing(inst)

    print(inst)
    ip = ctx.getConcreteRegisterValue(ctx.registers.rip)
