import xml.dom.minidom

import sys
import os
import hashlib
import re
import time
import intelhex
import chardet
from optparse import OptionParser


def find_start_address(__prj_path):
    __xml_dom = xml.dom.minidom.parse(str(__prj_path))
    __collection = __xml_dom.documentElement
    __ele = __collection.getElementsByTagName("OCR_RVCT4")[0]
    __start_address = int(__ele.getElementsByTagName(
        "StartAddress")[0].childNodes[0].data, 16)
    return __start_address


def get_encoding(_file):
    with open(_file, 'rb') as _f:
        tmp = chardet.detect(_f.read(1000))
        return tmp["encoding"]


def parse_config(_config_file):
    # 自动获取文件编码
    __config_f = open(_config_file, 'r', encoding=get_encoding(_config_file))
    if __config_f is None:
        return None
    __config = __config_f.read()

    # 查找项目名
    _list = re.findall(r'#define FIRMWARE_INFO_PROJ\s*\"(.+?)\"', __config)
    if len(_list) == 0:
        __prj_tag = "Unkonw"
    else:
        __prj_tag = _list[0]

    # 查找版本号
    _list = re.findall(r'#define FIRMWARE_INFO_VER\s*\"(.+?)\"', __config)
    if len(_list) == 0:
        __ver = "Unkonw"
    else:
        __ver = _list[0]

    # 查找flash基地址
    _list = re.findall(r'#define ROM_ONCHIP_BASE\s*\((.+?)\)', __config)
    if len(_list) == 0:
        return None
    else:
        __flash_base = int(_list[0], 16)

    # 查找固件偏移
    _list = re.findall(
        r'#define RUN_KERNEL_PART_OFFSET\s*\((.+?)\)', __config)
    if len(_list) == 0:
        return None
    else:
        __firm_off = int(_list[0], 16)

    return [__prj_tag, __ver, __flash_base, __firm_off]


def find_prj_file():
    _files = os.listdir('.')
    for _f in _files:
        if _f.endswith('.uvprojx') or _f.endswith('.uvproj'):
            return _f

    return None


#  Start here
parser = OptionParser()
parser.add_option("-k", "--kernel-dir",
                  dest="kernel_dir", default='./',
                  action="store", type="string",
                  help="Kernel project dir (default=\'.\')")
parser.add_option("-K", "--kernel-project",
                  dest="kernel_project", default='kernel.uvprojx',
                  action="store", type="string",
                  help="Kernel project name  (default=\'kernel.uvprojx\')")
parser.add_option("-b", "--bootloader-dir",
                  dest="bootloader_dir", default='../bootloader/',
                  action="store", type="string",
                  help="Bootloader project dir (default=\'../bootloader/\')")
parser.add_option("-c", "--configure-file",
                  dest="configure_file", default='boot_config.h',
                  action="store", type="string",
                  help="Configure file name (default=\'boot_config.h\')")
parser.add_option("-o", "--output",
                  dest="output", default='Output',
                  action="store", type="string",
                  help="Output path (default=\'./Output\')")
(options, args) = parser.parse_args()

# 提取boot_config.h中的配置
boot_path = options.bootloader_dir.rstrip('\\').rstrip('/')
if not os.path.exists(boot_path + '/' + options.configure_file):
    print('配置文件' + boot_path + '/' + options.configure_file + '不存在')
    sys.exit(1)
config = parse_config(boot_path + '/' + options.configure_file)
if config is None:
    print('配置文件' + boot_path + options.configure_file + '解析失败')
    sys.exit(1)

# 解析并校验内核启动地址
kernel_path = options.kernel_dir.rstrip('\\').rstrip('/')
if not os.path.exists(kernel_path + '/' + options.kernel_project):
    print('内核工程文件' + kernel_path + '/' + options.kernel_project + '不存在')
    sys.exit(1)
start_address = find_start_address(kernel_path + '/' + options.kernel_project)
flash_base = config[2]
kernel_offset = config[3]
if start_address != (flash_base + kernel_offset):
    print('[ERROR] 内核启动地址错误!请检查工程设置!')
    sys.exit(2)

kernel_bin_path = kernel_path + '/Output/kernel.bin'
boot_bin_path = boot_path + '/Output/boot.bin'
output_dir = options.output.rstrip('\\').rstrip('/')

print("\nPack tool run...")
print("KERNEL_BIN = " + kernel_bin_path)
print("BOOT_BIN =   " + boot_bin_path)
print("OUTPUT =     " + output_dir)
print("BASE =       " + hex(flash_base))
print("START_ADDR = " + hex(start_address))
print("OFFSET =     " + hex(kernel_offset))

if not os.path.exists(kernel_bin_path):
    print('[ERROR] 内核Bin文件不存在!')
    sys.exit(3)
kernel_bin = open(kernel_bin_path, 'rb')
kernel = kernel_bin.read()
kernel_bin.close()

if not os.path.exists(boot_bin_path):
    print('[ERROR] Bootloader Bin文件不存在!')
    sys.exit(4)

if not os.path.exists(output_dir):
    os.mkdir(output_dir)

#  获取内核信息
kernel_mtime = os.path.getmtime(kernel_bin_path)
kernel_size = os.path.getsize(kernel_bin_path)

#  计算内核MD5值
kernel_md5 = hashlib.md5(kernel).hexdigest()

# 输出FW文件
fw_file_path = output_dir + '\\' + 'sec_ota_' + \
    config[0] + '_' + config[1] + '.fw'
fw_file = open(fw_file_path, 'w+b')
fw_file.write(bytes('SFP', encoding='utf-8'))
fw_file.write(bytes(1))
fw_file.write(bytes(6))
if len(config[0]) > 32:
    fw_file.write(bytes(config[0][0:32], encoding='utf-8'))
else:
    fw_file.write(bytes(config[0], encoding='utf-8'))
    fw_file.write(bytes(32 - len(config[0])))

if len(config[1]) > 8:
    fw_file.write(bytes(config[0][0:8], encoding='utf-8'))
else:
    fw_file.write(bytes(config[1], encoding='utf-8'))
    fw_file.write(bytes(8 - len(config[1])))

fw_file.write(bytes(time.strftime("%Y-%m-%d %H:%M:%S",
              time.localtime(kernel_mtime)), encoding='utf-8'))
fw_file.write(bytes(5))
fw_file.write(int(kernel_size).to_bytes(4, 'little'))
fw_file.write(int(kernel_md5[0:32], 16).to_bytes(16, 'big'))
fw_file.write(bytes(2))
fw_file.write(kernel)
fw_file.close()

# 输出HEX文件
hex_file_path = output_dir + '\\' + 'sec_fct_' + \
    config[0] + '_' + config[1] + '.hex'
hex_data = intelhex.IntelHex()
hex_data.loadbin(fw_file_path, flash_base + kernel_offset - 96)
boot_hex_data = intelhex.IntelHex()
boot_hex_data.loadbin(boot_bin_path, flash_base)
hex_data.merge(boot_hex_data)
hex_data.tofile(hex_file_path, 'hex')

print("\n\nFirmware info ------------------------------")
print("packer:  PySFP")
print("proj:    " + config[0])
print("ver:     " + config[1])
print("time:    " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(kernel_mtime)))
print("size:    " + str(kernel_size) + 'bytes')
print("MD5:     <" + kernel_md5[0:32] + '>')
print("--------------------------------------------")
print("Firmware Pack Complete!")
sys.exit(0)
