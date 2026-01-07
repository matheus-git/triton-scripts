from triton import *

ctx = TritonContext(ARCH.X86_64)
BASE = 0x100000       
STACK = 0x200000

ctx.setConcreteMemoryAreaValue(STACK, b"\x00" * 0x1000) 
ctx.setConcreteRegisterValue(ctx.registers.rsp, STACK + 0x1000)
ctx.setConcreteRegisterValue(ctx.registers.rbp, STACK + 0x1000)

instructions = []
with open("instructions.txt") as f:
    for line in f:
        off, bytestr = line.split(":")
        off = int(off, 16)
        b = bytes(int(x, 16) for x in bytestr.split())
        addr = BASE + off
        instructions.append((addr, b))
        ctx.setConcreteMemoryAreaValue(addr, b)

rax = ctx.registers.rax
rdi = ctx.registers.rdi
ctx.symbolizeRegister(rax)
ctx.symbolizeRegister(rdi)

process = False
start_addr = BASE + 0x128A 
end_addr   = BASE + 0x1292

for addr, op in instructions:
    if addr == start_addr:
        process = True
    if addr == end_addr:
        process = False

    if process:
        inst = Instruction()
        inst.setOpcode(op)
        inst.setAddress(addr)
        ctx.processing(inst)

        print(f"{hex(addr)}: {inst} | RAX AST: {ctx.getRegisterAst(rax)} | RDI AST: {ctx.getRegisterAst(rdi)}")

ast = ctx.getAstContext()
rax_ast = ctx.getRegisterAst(rax)
rdi_ast = ctx.getRegisterAst(rdi)

constraint = ast.equal(rax_ast, ast.bv(1337, 64))

model = ctx.getModel(constraint)

for k, v in model.items():
    print(f"{k} = {v.getValue()}")