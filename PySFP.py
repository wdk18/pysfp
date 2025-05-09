# 导入必要的模块
import hashlib
import os
import re
import sys
import time
import xml.dom.minidom
from ctypes import *
from optparse import OptionParser

import chardet
import git
import intelhex


# struct firmware_header
# {
#    char pack_tool[4];
#    char compress_type;
#    char encrypt_type;
#    char reserve1[4];
#    char proj_tag[32];
#    char version[8];
#    char create_time[24];
#    unsigned int size;
#    char md5[8];
#    char git_revision[8];
#    char reserve2[2];
# };
class FirmwareHeader(Structure):
    _pack_ = 1
    _fields_ = [
        ('pack_tool', 4 * c_char),
        ('compress_type', c_ubyte),
        ('encrypt_type', c_ubyte),
        ('reserve1', 4 * c_char),
        ('proj_tag', 32 * c_char),
        ('version', 8 * c_char),
        ('create_time', 24 * c_char),
        ('size', c_uint32),
        ('md5', 8 * c_char),
        ('git_revision', 8 * c_char),
        ('reserve2', 2 * c_char),
    ]


# 获取启动地址
def find_start_address(__prj_path):
    __xml_dom = xml.dom.minidom.parse(str(__prj_path))
    __collection = __xml_dom.documentElement
    __ele = __collection.getElementsByTagName("OCR_RVCT4")[0]
    __start_address = int(__ele.getElementsByTagName(
        "StartAddress")[0].childNodes[0].data, 16)
    return __start_address


# 获取文件编码
def get_encoding(_file):
    with open(_file, 'rb') as _f:
        tmp = chardet.detect(_f.read(1000))
        return tmp["encoding"]


# 解析配置文件
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


# 查找项目文件
def find_prj_file():
    _files = os.listdir('.')
    for _f in _files:
        if _f.endswith('.uvprojx') or _f.endswith('.uvproj'):
            return _f

    return None


def string_to_bytearray(_str: str, _len: int):
    if _len == 0:
        return None
    if len(_str) >= _len:
        _bytearray = _str[:_len].encode("utf-8")
    else:
        _bytearray = _str.encode("utf-8") + b'\x00' * (_len - len(_str))
    return _bytearray


# 获取Git提交版本号，输出为长度为8的字符串
def get_git_commit_id():
    try:
        repo = git.Repo(search_parent_directories=True)
        if repo.is_dirty(untracked_files=True) or repo.index.diff("HEAD"):
            commit_sha = repo.head.commit.hexsha[:7] + '*'
        else:
            commit_sha = repo.head.commit.hexsha[:8]
        return commit_sha
    except git.InvalidGitRepositoryError:
        return "Unknown*"


# 主程序
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

# 获取内核和Bootloader的二进制文件路径
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

# 检查文件存在性
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
firmware_header = FirmwareHeader()
firmware_header.pack_tool = string_to_bytearray('SFP', 4)
firmware_header.proj_tag = string_to_bytearray(config[0], 32)
firmware_header.version = bytes(config[1], encoding="utf-8")
firmware_header.create_time = bytes(time.strftime("%Y-%m-%d %H:%M:%S",
                                                  time.localtime(kernel_mtime)), encoding='utf-8')
firmware_header.size = kernel_size
firmware_header.md5 = int(kernel_md5[0:16], 16).to_bytes(8, 'big')
firmware_header.git_revision = get_git_commit_id().encode("utf-8")
fw_file.write(firmware_header)
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
print("packer:      PySFP")
print("proj:        " + config[0])
print("ver:         " + config[1])
print("time:        " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(kernel_mtime)))
print("size:        " + str(kernel_size) + 'bytes')
print("MD5:         <" + kernel_md5[0:32] + '>')
print("Commit SHA:  " + get_git_commit_id())
print("--------------------------------------------")
print("Firmware Pack Complete!")
sys.exit(0)
