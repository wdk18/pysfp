# PySFP 

基于Python编写的SEC平台固件打包器

## 包依赖

  - intelhex
  - chardet

## 生成方法

  1. 使用 `pip` 安装 `pyinstaller` 包
  2. 在目录下调用如下命令
     ```powershell
     pyinstaller -F -i .\main.ico .\PySFP.py
     ```
  3. 可执行文件会输出到 ` dist\PySFP.exe ` 路径下