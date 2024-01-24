from xml.dom.minidom import parse
import xml.dom.minidom

import sys
import os
import hashlib
import re
import time
import intelhex
import chardet


def find_start_address(__prj_path):
    __xml_dom = xml.dom.minidom.parse(str(__prj_path))
    __collection = __xml_dom.documentElement
    __ele = __collection.getElementsByTagName("OCR_RVCT4")[0]
    __start_address = int(__ele.getElementsByTagName("StartAddress")[0].childNodes[0].data, 16)
    return __start_address


def parse_config(__bsp_dir):
    __config_file = open(__bsp_dir + '\\config.h', 'rb')
    encode = chardet.detect(__config_file.read()).get("encoding")
    __config_file.close()
    __config_file = open(__bsp_dir + '\\config.h', 'r', encoding=encode)
    if __config_file is None:
        return None
    __config = __config_file.read()
    __prj_tag = re.findall(r'#define FIRMWARE_INFO_PROJ\s*\"(.+?)\"', __config)[0]
    __ver = re.findall(r'#define FIRMWARE_INFO_VER\s*\"(.+?)\"', __config)[0]
    _config_list = [__prj_tag, __ver]
    return _config_list


def find_prj_file():
    _files = os.listdir('.')
    for _f in _files:
        if _f.endswith('.uvprojx') or _f.endswith('.uvproj'):
            return _f

    return None


#  Start here
if len(sys.argv) < 7:
    print('[Usage]')
    print('  ' + sys.argv[
        0] + ' [BSP_DIR] [KERNEL_BIN_PATH] [BOOT_BIN_PATH] [OUTPUT_DIR] [KERNEL_OFFSET] [FLASH_BASE]')
    sys.exit(1)

bsp_dir = sys.argv[1]
prj_file = find_prj_file()
if prj_file is None:
    print('[ERROR] 无法找到工程文件!')
    sys.exit(1)

start_address = find_start_address(prj_file)
kernel_bin_path = sys.argv[2]
boot_bin_path = sys.argv[3]
output_dir = str(sys.argv[4])
if output_dir.endswith('\\') or output_dir.endswith('/'):
    output_dir = output_dir[:-1]
kernel_offset = int(sys.argv[5], 16)
flash_base = int(sys.argv[6], 16)

print("\nPack tool run...")
print("BSP_DIR =    " + bsp_dir)
print("KERNEL_BIN = " + kernel_bin_path)
print("BOOT_BIN =   " + boot_bin_path)
print("OUTPUT =     " + output_dir)
print("BASE =       " + hex(flash_base))
print("START_ADDR = " + hex(start_address))
print("OFFSET =     " + hex(kernel_offset))

if start_address != (flash_base + kernel_offset + 96):
    print('[ERROR] 内核启动地址错误!请检查工程设置!')
    sys.exit(2)

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

#  从config.h中获取版本号和项目标签
config = parse_config(bsp_dir)

#  获取内核信息
kernel_mtime = os.path.getmtime(kernel_bin_path)
kernel_size = os.path.getsize(kernel_bin_path)

#  计算内核MD5值
kernel_md5 = hashlib.md5(kernel).hexdigest()

# 输出FW文件
fw_file_path = output_dir + '\\' + 'sec_ota_' + config[0] + '_' + config[1] + '.fw'
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

fw_file.write(bytes(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(kernel_mtime)), encoding='utf-8'))
fw_file.write(bytes(5))
fw_file.write(int(kernel_size).to_bytes(4, 'little'))
fw_file.write(int(kernel_md5[0:32], 16).to_bytes(16, 'big'))
fw_file.write(bytes(2))
fw_file.write(kernel)
fw_file.close()

# 输出HEX文件
hex_file_path = output_dir + '\\' + 'sec_fct_' + config[0] + '_' + config[1] + '.hex'
hex_data = intelhex.IntelHex()
hex_data.loadbin(fw_file_path, flash_base + kernel_offset)
boot_hex_data = intelhex.IntelHex()
boot_hex_data.loadbin(boot_bin_path, flash_base)
hex_data.merge(boot_hex_data)
hex_data.tofile(hex_file_path, 'hex')

print("\n\nFirmware info -----------------------")
print("packer:  PySFP")
print("proj:    " + config[0])
print("ver:     " + config[1])
print("time:    " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(kernel_mtime)))
print("size:    " + str(kernel_size) + 'bytes')
print("MD5:     <" + kernel_md5[0:32] + '>')
print("-------------------------------------")
print("Firmware Pack Complete!")
