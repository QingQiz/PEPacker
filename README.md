Code Flow:

`loader.cpp` is responsible for reading a segment of data from its own `PACKED_SEC_NAME` section, decoding it, and loading it as a PE program.
`packer.cpp` is responsible for modifying the loader, embedding the program to be packed into the `PACKED_SEC_NAME` section of the loader.

Specifically, `loader.cpp` will be compiled into `loader.exe`, and `obcopy` will be used to package the entire `loader.exe` into `packer.exe`.
During runtime, `packer.exe` will read and modify the `loader.exe` embedded within its own program,
encode `topack.exe` and store it in the `PACKED_SEC_NAME` section of `loader.exe`, and finally release it to a file, thereby completing the packing process.

```
      packer.exe                                                                                                 
+---------------------+                                                                                          
|    packer.exe.text  |                                                                                          
|    packer.exe.data  |                                                                                          
|    ........         |                                                                                          
|                     |           +------------------+                packed.exe                                 
|-------------------- |           |                  |                                                           
|                     |           |                  |           +-------------------+                           
|   loader.exe PE     |           |      loader.exe  | --\       |  loader.exe.text  |                           
|                     |-----------+                  |    ---\   |  loader.exe.data  |                           
|                     |           |                  |        ---|  ......           |                           
+---------------------+           +------------------+           |                   |                           
                                                                 |------------------ |                           
                                                                 |  encoded          |                           
+---------------------+              +-----------------+         |  topack.exe       |                           
|                     |              |                 |        --                   |                           
|                     |              |                 |      -/ |                   |                           
|                     |              |                 |    -/   +-------------------+                           
|    topack.exe       |              |   encoded       |  -/                                                     
|                     |--------------+   topack.exe    |-/                                                       
|                     |              |                 |                                                         
|                     |              |                 |                                                         
|                     |              |                 |                                                         
+---------------------+              +-----------------+                                                         
```