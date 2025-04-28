代码流程：

loader.cpp 负责从自身的PACKED_SEC_NAME节读取一段数据，将其解码后作为PE程序加载
packer.cpp 负责对修改loader，将要打包的程序放入loader的PACKED_SEC_NAME节中

具体来说，loader.cpp 将被编译为 loader.exe，使用 obcopy 将 loader.exe 整体打包进 packer.exe 中。
在运行时，packer.exe 将会读取并修改自身程序中打包的 loader.exe，
将 topack.exe 编码并存入 loader.exe 的 PACKED_SEC_NAME 节中，最后将其释放到文件，从而完成加壳。

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