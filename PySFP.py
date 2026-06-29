#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PySFP - Python Secure Firmware Packer

固件打包工具，用于将内核和 Bootloader 二进制文件打包成固件文件。

功能特性:
    - 解析配置文件获取项目信息
    - 读取内核和 Bootloader 的二进制文件
    - 生成固件文件（.fw）和 Intel HEX 文件
    - 自动计算 MD5 校验值
    - 集成 Git 提交版本号

使用方法:
    python PySFP.py -k <kernel_dir> -b <bootloader_dir> -c <config_file> -o <output_dir>

命令行参数:
    -k, --kernel-dir          内核项目目录 (默认: '.')
    -K, --kernel-project      内核工程文件名 (默认: 'kernel.uvprojx')
    -b, --bootloader-dir      Bootloader 项目目录 (默认: '../bootloader/')
    -c, --configure-file      配置文件名 (默认: 'boot_config.h')
    -o, --output              输出目录 (默认: 'Output')

作者：PySFP Team
版本：1.0.0
"""

import hashlib
import os
import re
import sys
import time
import xml.dom.minidom
from ctypes import (
    Structure,
    c_char,
    c_ubyte,
    c_uint32,
)
from optparse import OptionParser

import chardet
import git
import intelhex


class FirmwareHeader(Structure):
    """固件文件头结构体。

    该结构体定义了固件文件的头部格式，包含以下字段:
        - pack_tool: 打包工具标识 (4 字节)
        - compress_type: 压缩类型 (1 字节)
        - encrypt_type: 加密类型 (1 字节)
        - reserve1: 保留字段 (4 字节)
        - proj_tag: 项目标签 (32 字节)
        - version: 版本号 (8 字节)
        - create_time: 创建时间 (24 字节)
        - size: 固件大小 (4 字节)
        - md5: MD5 校验值 (8 字节)
        - git_revision: Git 提交版本号 (8 字节)
        - reserve2: 保留字段 (2 字节)

    总大小：96 字节
    """

    _pack_ = 1
    _fields_ = [
        ("pack_tool", 4 * c_char),
        ("compress_type", c_ubyte),
        ("encrypt_type", c_ubyte),
        ("reserve1", 4 * c_char),
        ("proj_tag", 32 * c_char),
        ("version", 8 * c_char),
        ("create_time", 24 * c_char),
        ("size", c_uint32),
        ("md5", 8 * c_char),
        ("git_revision", 8 * c_char),
        ("reserve2", 2 * c_char),
    ]


def find_start_address(prj_path: str) -> int:
    """从 UVProj 项目文件中提取内核启动地址。

    Args:
        prj_path: UVProj 项目文件路径 (.uvprojx 或 .uvproj)

    Returns:
        内核启动地址（十六进制整数）

    Raises:
        xml.dom.minidom.ParseError: XML 解析失败
        IndexError: 项目文件结构不符合预期
    """
    xml_dom = xml.dom.minidom.parse(str(prj_path))
    collection = xml_dom.documentElement
    ele = collection.getElementsByTagName("OCR_RVCT4")[0]
    start_address = int(
        ele.getElementsByTagName("StartAddress")[0].childNodes[0].data, 16
    )
    return start_address


def get_encoding(file_path: str) -> str | None:
    """检测文件的编码格式。

    Args:
        file_path: 要检测编码的文件路径

    Returns:
        检测到的编码名称，如果无法检测则返回 None
    """
    with open(file_path, "rb") as f:
        tmp = chardet.detect(f.read(1000))
        return tmp["encoding"]


def parse_config(config_file: str) -> list | None:
    """解析配置文件，提取固件相关信息。

    从配置文件中提取以下信息:
        - 项目名称 (FIRMWARE_INFO_PROJ)
        - 版本号 (FIRMWARE_INFO_VER)
        - 是否启用安全加密 (FIRMWARE_SECURITY)
        - Flash 基地址 (ROM_ONCHIP_BASE)
        - 固件偏移地址 (RUN_KERNEL_PART_OFFSET)

    Args:
        config_file: 配置文件路径 (通常是 boot_config.h)

    Returns:
        包含以下元素的列表 [项目名，版本号，Flash 基地址，固件偏移，是否加密]，
        如果解析失败则返回 None
    """
    encoding = get_encoding(config_file)
    if encoding is None:
        encoding = "utf-8"

    with open(config_file, "r", encoding=encoding) as config_f:
        config = config_f.read()

    # 查找项目名
    proj_list = re.findall(r"#define FIRMWARE_INFO_PROJ\s*\"(.+?)\"", config)
    if len(proj_list) == 0:
        prj_tag = "Unknown"
    else:
        prj_tag = proj_list[0]

    # 查找版本号
    ver_list = re.findall(r"#define FIRMWARE_INFO_VER\s*\"(.+?)\"", config)
    if len(ver_list) == 0:
        ver = "Unknown"
    else:
        ver = ver_list[0]

    # 查找加密标志
    secure_list = re.findall(r"#define FIRMWARE_SECURITY", config)
    if len(secure_list) == 0:
        use_secure = False
    else:
        use_secure = True

    # 查找 Flash 基地址
    flash_list = re.findall(r"#define ROM_ONCHIP_BASE\s*\((.+?)\)", config)
    if len(flash_list) == 0:
        return None
    else:
        flash_base = int(flash_list[0], 16)

    # 查找固件偏移
    offset_list = re.findall(r"#define RUN_KERNEL_PART_OFFSET\s*\((.+?)\)", config)
    if len(offset_list) == 0:
        return None
    else:
        firm_off = int(offset_list[0], 16)

    return [prj_tag, ver, flash_base, firm_off, use_secure]


def find_prj_file() -> str | None:
    """在当前目录查找 UVProj 项目文件。

    Returns:
        找到的第一个 .uvprojx 或 .uvproj 文件名，如果未找到则返回 None
    """
    files = os.listdir(".")
    for f in files:
        if f.endswith(".uvprojx") or f.endswith(".uvproj"):
            return f
    return None


def string_to_bytearray(input_str: str, length: int) -> bytes | None:
    """将字符串转换为固定长度的字节数组。

    如果字符串长度小于指定长度，则用零字节填充。
    如果字符串长度大于等于指定长度，则截取前 length 个字符。

    Args:
        input_str: 输入字符串
        length: 目标字节数组长度

    Returns:
        固定长度的字节数组，如果 length 为 0 则返回 None
    """
    if length == 0:
        return None
    if len(input_str) >= length:
        bytearray_result = input_str[:length].encode("utf-8")
    else:
        bytearray_result = input_str.encode("utf-8") + b"\x00" * (
            length - len(input_str)
        )
    return bytearray_result


def get_git_commit_id() -> str:
    """获取当前 Git 仓库的提交版本号。

    返回长度为 8 的字符串，如果工作区有未提交的更改，则末尾添加 '*' 标记。

    Returns:
        Git 提交版本号（前 8 个字符），如果无法获取则返回 "Unknown*"
    """
    try:
        repo = git.Repo(search_parent_directories=True)
        if repo.is_dirty(untracked_files=True) or repo.index.diff("HEAD"):
            commit_sha = repo.head.commit.hexsha[:7] + "*"
        else:
            commit_sha = repo.head.commit.hexsha[:8]
        return commit_sha
    except git.InvalidGitRepositoryError:
        return "Unknown*"


def is_file_a_newer(file_a_path, file_b_path):
    # 获取文件 A 的最后修改时间
    time_a = os.path.getmtime(file_a_path)
    # 获取文件 B 的最后修改时间
    time_b = os.path.getmtime(file_b_path)

    # 比较时间，返回结果
    return time_a > time_b

def main() -> None:
    """主程序入口函数。

    执行固件打包流程:
        1. 解析命令行参数
        2. 读取配置文件
        3. 验证内核启动地址
        4. 读取内核和 Bootloader 二进制文件
        5. 生成固件文件和 HEX 文件
    """
    # 配置命令行参数解析器
    parser = OptionParser()
    parser.add_option(
        "-k",
        "--kernel-dir",
        dest="kernel_dir",
        default="./",
        action="store",
        type="string",
        help="内核项目目录 (默认:'.')",
    )
    parser.add_option(
        "-K",
        "--kernel-project",
        dest="kernel_project",
        default="kernel.uvprojx",
        action="store",
        type="string",
        help="内核工程文件名 (默认:'kernel.uvprojx')",
    )
    parser.add_option(
        "-b",
        "--bootloader-dir",
        dest="bootloader_dir",
        default="../bootloader/",
        action="store",
        type="string",
        help="Bootloader 项目目录 (默认:'../bootloader/')",
    )
    parser.add_option(
        "-c",
        "--configure-file",
        dest="configure_file",
        default="boot_config.h",
        action="store",
        type="string",
        help="配置文件名 (默认:'boot_config.h')",
    )
    parser.add_option(
        "-o",
        "--output",
        dest="output",
        default="Output",
        action="store",
        type="string",
        help="输出目录 (默认:'./Output')",
    )
    options, args = parser.parse_args()

    # 提取 boot_config.h 中的配置
    boot_path = options.bootloader_dir.rstrip("\\").rstrip("/")
    config_file_path = boot_path + "/" + options.configure_file
    if not os.path.exists(config_file_path):
        print(f"配置文件 {config_file_path} 不存在")
        sys.exit(1)

    config = parse_config(config_file_path)
    if config is None:
        print(f"配置文件 {config_file_path} 解析失败")
        sys.exit(1)

    # 解析并校验内核启动地址
    kernel_path = options.kernel_dir.rstrip("\\").rstrip("/")
    kernel_project_path = kernel_path + "/" + options.kernel_project
    if not os.path.exists(kernel_project_path):
        print(f"内核工程文件 {kernel_project_path} 不存在")
        sys.exit(1)

    try:
        start_address = find_start_address(kernel_project_path)
    except Exception as e:
        print(f"[ERROR] 解析内核工程文件失败：{e}")
        sys.exit(2)

    flash_base = config[2]
    kernel_offset = config[3]
    if start_address != (flash_base + kernel_offset):
        print("[ERROR] 内核启动地址错误！请检查工程设置!")
        sys.exit(2)

    # 获取内核和 Bootloader 的二进制文件路径
    kernel_bin_path = kernel_path + "/Output/kernel.bin"
    boot_bin_path = boot_path + "/Output/boot.bin"
    output_dir = options.output.rstrip("\\").rstrip("/")

    print("\nPack tool run...")
    print(f"KERNEL_BIN = {kernel_bin_path}")
    print(f"BOOT_BIN =   {boot_bin_path}")
    print(f"OUTPUT =     {output_dir}")
    print(f"BASE =       {hex(flash_base)}")
    print(f"START_ADDR = {hex(start_address)}")
    print(f"OFFSET =     {hex(kernel_offset)}")

    # 检查文件存在性并读取内核二进制文件
    if not os.path.exists(kernel_bin_path):
        print("[ERROR] 内核 Bin 文件不存在!")
        sys.exit(3)

    with open(kernel_bin_path, "rb") as kernel_bin:
        kernel = kernel_bin.read()

    if not os.path.exists(boot_bin_path):
        print("[ERROR] Bootloader Bin 文件不存在!")
        sys.exit(4)

    # 创建输出目录（如果不存在）
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    # 获取内核信息
    kernel_mtime = os.path.getmtime(kernel_bin_path)
    kernel_size = os.path.getsize(kernel_bin_path)

    # 计算内核 MD5 值
    kernel_md5 = hashlib.md5(kernel).hexdigest()

    # 输出 FW 文件

    fw_file_path = (
        output_dir
        + "\\"
        + "sec_ota_"
        + config[0]
        + "_"
        + config[1]
        + ("_secured" if config[3] else "")
        + ".fw"
    )
    with open(fw_file_path, "w+b") as fw_file:
        firmware_header = FirmwareHeader()
        firmware_header.pack_tool = string_to_bytearray("SFP", 4)
        firmware_header.proj_tag = string_to_bytearray(config[0], 32)
        firmware_header.version = bytes(config[1], encoding="utf-8")
        firmware_header.create_time = bytes(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(kernel_mtime)),
            encoding="utf-8",
        )
        firmware_header.size = kernel_size
        firmware_header.md5 = int(kernel_md5[0:16], 16).to_bytes(8, "big")
        firmware_header.git_revision = get_git_commit_id().encode("utf-8")
        fw_file.write(firmware_header)
        fw_file.write(kernel)

    # 输出 HEX 文件
    hex_file_path = (
        output_dir
        + "\\"
        + "sec_fct_"
        + config[0]
        + "_"
        + config[1]
        + ("_secured" if config[3] else "")
        + ".hex"
    )
    hex_data = intelhex.IntelHex()
    hex_data.loadbin(fw_file_path, flash_base + kernel_offset - 96)
    boot_hex_data = intelhex.IntelHex()
    boot_hex_data.loadbin(boot_bin_path, flash_base)
    hex_data.merge(boot_hex_data)
    hex_data.tofile(hex_file_path, "hex")

    print("\n\nFirmware info ------------------------------")
    print("packer:      PySFP")
    print(f"proj:        {config[0]}")
    print(f"ver:         {config[1]}")
    print(
        f"time:        {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(kernel_mtime))}"
    )
    print(f"size:        {kernel_size} bytes")
    print(f"MD5:         <{kernel_md5[0:32]}>")
    print(f"Commit SHA:  {get_git_commit_id()}")
    print("--------------------------------------------")
    print("Firmware Pack Complete!")
    if config[4]:
        print("[WARNING] 工程已启用固件保护，烧写当前boot后将无法进行调试。")
        print(
            f"          如无需保护，请移除'{config_file_path}'文件中的'FIRMWARE_SECURITY'宏定义, 并重新编译烧写boot"
        )
    else:
        print("工程未启用固件保护")
    if is_file_a_newer(config_file_path, boot_bin_path):
        print("[WARNING] @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
        print(f"[WARNING] @ 修改 'boot_config.h' 后还没有重新编译Boot @")
        print("[WARNING] @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    sys.exit(0)


if __name__ == "__main__":
    main()
