# The Perfect Mapper

This mapper provides a simple header file that will allow the user
to use the `EAT` as a `IAT` for symbols that are not exported by 
modules like `ntoskrnl.exe` in this way we eliminate the need for 
pattern scanning and offsets. Every symbol that is requested through the 
special `EAT` will get resolved by the mapper through `PDB` parsing, 
as long as the user can reach `Microsoft's symbols server` and the names
provided in the `EAT` are correct.
`( pm.h contains the needed macros )`

### Supports:
- [x] Symbols
- [x] Pointers
- [x] Structure offsets
- [x] Structure size

This can easily work even without internet as long as the needed `.pdb`-s
are saved in the cache directory.

### Credits & Resources:
- [KdMapper by: TheCruz](https://github.com/TheCruZ/kdmapper)
- [Microsoft PDB](https://github.com/microsoft/microsoft-pdb)
<br />
- Th3Spl
