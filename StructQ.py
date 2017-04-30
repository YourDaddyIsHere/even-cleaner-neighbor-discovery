from struct import pack, unpack_from, Struct
_struct_Q = Struct(">Q")
_global_time = 1
g = int(_global_time)
_struct_Q.pack(g)