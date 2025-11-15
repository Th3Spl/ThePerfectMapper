# The Perfect Mapper

This mapper provides a simple header file that will allow the user
to use the `EAT` as a `IAT` for symbols that are not exported by 
modules like `ntoskrnl.exe` in this way we eliminate the need for 
pattern scanning and offsets. Every symbol that is requested through the 
special `EAT` will get resolved by the mapper through `PDB` parsing, 
as long as the user can reach `Microsoft's symbols server` and the names
provided in the `EAT` are correct.