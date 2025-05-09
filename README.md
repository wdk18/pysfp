# PySFP 

基于Python编写的SEC平台固件打包器

## 包依赖

  - intelhex
  - chardet
  - gitpython

## 生成单可执行文件方法

  1. 使用 `pip` 安装 `pyinstaller` 包
  2. 在目录下调用如下命令
     ```powershell
     pyinstaller -D -i .\main.ico .\PySFP.py
     ```
     ***注：*** windows平台下直接使用 *-F* 参数输出单可执行文件会有启动缓慢的问题，linux平台考虑直接使用 *-F* 参数
  3. 文件会输出到 ` dist\PySFP ` 路径下
  4. 使用 ` Enigma Virtual Box ` 打包输出单可执行文件

### 生成注意事项
