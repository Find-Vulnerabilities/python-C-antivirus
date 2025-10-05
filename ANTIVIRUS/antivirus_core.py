import os
import hashlib
import time
import threading
import json
import math
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import psutil
import codecs
import logging
import sys
import multiprocessing
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import tempfile
import winshell
import ctypes
from ctypes import wintypes
import win32api
import win32con
import win32process
# 在文件顶部添加新导入
import win32security
import ntsecuritycon as con
from win32com.shell import shell, shellcon
import win32job  # 新增导入
import subprocess
import platform
import urllib.request

# ========== 增强的C底层控制模块 ==========
from ctypes import windll, WinDLL, WinError, Structure, POINTER, byref, c_ulong, c_void_p, c_char_p, c_wchar_p, sizeof, c_int
from ctypes.wintypes import DWORD, HANDLE, BOOL, ULONG, LPCWSTR, LPCSTR, WORD

kernel32 = windll.kernel32
advapi32 = windll.advapi32
ntdll = WinDLL('ntdll')

PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x1F0FFF

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", DWORD),
        ("PartitionId", WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)
    ]

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", wintypes.DWORD),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD)
    ]

kernel32.VirtualQueryEx.argtypes = [HANDLE, c_void_p, POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.ReadProcessMemory.argtypes = [HANDLE, c_void_p, c_void_p, ctypes.c_size_t, POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = BOOL

kernel32.GetSystemInfo.argtypes = [POINTER(SYSTEM_INFO)]
kernel32.GetSystemInfo.restype = None

ntdll.NtQuerySystemInformation.argtypes = [ULONG, c_void_p, ULONG, POINTER(ULONG)]
ntdll.NtQuerySystemInformation.restype = ULONG
# ========== END 增强的C底层控制模块 ==========

# 在配置部分添加隔离区路径
QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
# ==================== YARA Support ====================
try:
    import yara
    YARA_SUPPORT = True
except Exception as e:
    YARA_SUPPORT = False
    logging.warning(
        "yara-python library not installed or failed to load: %s\n"
        "If you have installed it via pip but still get errors, it's usually due to missing libyara.dll or dependencies.\n"
        "Solutions:\n"
        "1. Check if Python is 64-bit or 32-bit, libyara.dll must match.\n"
        "2. Download the corresponding wheel from https://github.com/VirusTotal/yara-python/releases, or download libyara.dll from https://github.com/VirusTotal/yara/releases, and place it in Python's DLLs directory or PATH.\n"
        "3. If still not working, try installing with conda (conda install -c conda-forge yara-python) or use official wheels.\n"
        "4. You can ignore this warning, the program will automatically disable YARA detection, other functions are not affected."
        % e
    )
# ================================================

# ==================== Configuration ====================
MONITOR_DIR = os.path.expanduser("~")
DELETION_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deletion_logs")
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antivirus.log")
MAX_WORKERS = max(2, multiprocessing.cpu_count() - 1)

# Whitelisted SHA256 hashes
WHITELISTED_HASHES = [
    "ca8c0a2a00f1d6f6da076d1d61fa706e82df57ed2b12ae3b3c36f4f73556b2ec",
    "fdb20300b1d03f27a9ae9e82f9f4c49d58efd558aeecb44aa8927964663b2d06",
    "896e7edb5c8b1d6ab794427640ddeea33c1dded54469a0c2ce2aceb56f0c0408",
    "3e641691c4d0b488df5a3b8ec926602950df7e06268ef8cb4fbfc54b0bcd26aa",
    "036aff7f76e9573ee073a9422121a844ac32727754abf17510ec16568ede18b7",
    "e698410e1b8e5b2875aa8b4d01fe6e4f0bf354f40d92925c4e3503d7fd1ec208",
    "e05a0e0d87c0af1cbcb5d6da9477c673cf55b44a7916a6ebdc4f3ea1072bfb06",
    "4f3adc5c61f88571cf20caaba5308eba9d1a9d944b22df24de3e31d6e31619ad",
    "a2b580321650a9e249e253eff90096981876323fbbccd0436af173ad6759b3a1",
    "69c8e5bbab050b271633dd64905a570e1806cbd0afd94e6b24a07b47dab43d64",
    "c35dec015bae2369d278435f0ba3bd61445a9571b02136b39044712​​8054c0448",
    "d8ee3eb9725b14981aeca1cb2e9e984d39d6e8c6f6cec7f8a6d1cd4b15f7b45b",
    "522a918a423f6167e4f0a93b3b6dc06b43b53b6ce424a5345bdf56472b30eb31",
    "7f59224522d2c8ebb0eb23598e0c3719385db417f0a5997defe7a6c6e52fbfd8",
    "3fedf64d8e2fe8084fbf8d1eb5c1f93de75f321070f6cecfeaa7d8b4d79c16c7",
    "5e97e7d15609fe298f87a8891e5f8ecc2bfd4e196531349a0b7145fab3dd9684",
    "522a918a423f6167e4f0a93b3b6dc06b43b53b6ce424a5345bdf56472b30eb31",
    "a7bd56874f1aee9d42805667581c48a7184c932428fca420742b306307d6e5c4",
    "2d910cd17814c4718f7c6fd099232a70e8d38469efe6ccc414c6e956fd1c36fa",















]
# ================================================

# Configure logging
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
if hasattr(sys.stdout, 'buffer'):
    stream_handler = logging.StreamHandler(codecs.getwriter('utf-8')(sys.stdout.buffer))
else:
    stream_handler = logging.StreamHandler(sys.stdout)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[file_handler, stream_handler]
)
logger = logging.getLogger(__name__)

os.makedirs(DELETION_LOG_DIR, exist_ok=True)

# ==================== Utility Functions ====================
def is_system_process(pid):
    """使用更低级的方法检查进程是否为系统进程"""
    try:
        process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not process_handle:
            return False
        token_handle = HANDLE()
        if not advapi32.OpenProcessToken(process_handle, win32con.TOKEN_QUERY, byref(token_handle)):
            kernel32.CloseHandle(process_handle)
            return False
        token_elevation = DWORD()
        token_elevation_size = DWORD()
        if not advapi32.GetTokenInformation(
            token_handle,
            win32security.TokenElevation,
            byref(token_elevation),
            sizeof(token_elevation),
            byref(token_elevation_size)
        ):
            kernel32.CloseHandle(token_handle)
            kernel32.CloseHandle(process_handle)
            return False
        kernel32.CloseHandle(token_handle)
        kernel32.CloseHandle(process_handle)
        return token_elevation.value == 1
    except Exception:
        return False

def terminate_process(pid):
    """使用底层API强制终止进程"""
    try:
        process_handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not process_handle:
            return False
        result = kernel32.TerminateProcess(process_handle, 0)
        kernel32.CloseHandle(process_handle)
        return bool(result)
    except Exception as e:
        logger.error(f"Failed to terminate process {pid}: {e}")
        return False

def suspend_process(pid):
    """使用底层API挂起进程"""
    try:
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            return False
        nt_suspend_process = getattr(ntdll, 'NtSuspendProcess', None)
        if nt_suspend_process:
            nt_suspend_process.argtypes = [HANDLE]
            nt_suspend_process.restype = ULONG
            status = nt_suspend_process(process_handle)
            kernel32.CloseHandle(process_handle)
            return status == 0
        else:
            kernel32.CloseHandle(process_handle)
            return False
    except Exception as e:
        logger.error(f"Failed to suspend process {pid}: {e}")
        return False

def resume_process(pid):
    """使用底层API恢复挂起的进程"""
    try:
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            return False
        nt_resume_process = getattr(ntdll, 'NtResumeProcess', None)
        if nt_resume_process:
            nt_resume_process.argtypes = [HANDLE]
            nt_resume_process.restype = ULONG
            status = nt_resume_process(process_handle)
            kernel32.CloseHandle(process_handle)
            return status == 0
        else:
            kernel32.CloseHandle(process_handle)
            return False
    except Exception as e:
        logger.error(f"Failed to resume process {pid}: {e}")
        return False

def get_process_memory_map(pid):
    """使用底层API获取进程内存映射"""
    memory_map = []
    try:
        process_handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid
        )
        if not process_handle:
            return memory_map
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        address = system_info.lpMinimumApplicationAddress
        max_address = system_info.lpMaximumApplicationAddress
        while address < max_address:
            mbi = MEMORY_BASIC_INFORMATION()
            result = kernel32.VirtualQueryEx(
                process_handle,
                address,
                byref(mbi),
                sizeof(mbi)
            )
            if result == 0:
                break
            if mbi.State == MEM_COMMIT:
                memory_info = {
                    'addr': mbi.BaseAddress,
                    'size': mbi.RegionSize,
                    'protect': mbi.Protect,
                    'state': mbi.State,
                    'type': mbi.Type
                }
                memory_map.append(memory_info)
            address += mbi.RegionSize
        kernel32.CloseHandle(process_handle)
    except Exception as e:
        logger.error(f"Failed to get memory map for process {pid}: {e}")
    return memory_map

def scan_process_memory(pid, engine):
    """使用 scan.dll 掃描進程內存（優先），否則用原本方法"""
    if DLL_LOADED and scan_dll:
        try:
            result = scan_dll.scan_process_memory(int(pid))
            if result:
                rule_names = ctypes.string_at(result).decode('utf-8')
                scan_dll.free_memory(result)
                return True, f"YARA match in memory: {rule_names}"
            return False, "No malicious patterns found"
        except Exception as e:
            logger.error(f"DLL memory scan error: {pid} - {e}")
    # fallback
    if is_system_process(pid):
        return False, "System process skipped"
    try:
        memory_map = get_process_memory_map(pid)
        if not memory_map:
            return False, "No accessible memory regions"
        suspicious_count = 0
        for mem_info in memory_map:
            if (mem_info['protect'] & PAGE_EXECUTE_READWRITE or
                mem_info['protect'] & PAGE_EXECUTE_WRITECOPY):
                logger.warning(f"Suspicious memory region in PID {pid}: 0x{mem_info['addr']:X} - Protection: 0x{mem_info['protect']:X}")
                suspicious_count += 1
        if suspicious_count > 3:
            return True, f"Multiple suspicious memory regions found ({suspicious_count})"
        return False, "No malicious patterns found"
    except Exception as e:
        logger.error(f"Error scanning memory for process {pid}: {e}")
        return False, f"Scan error: {str(e)}"

# ====== 新增: 載入 scan.dll ======
SCAN_DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan.dll')
scan_dll = None
DLL_LOADED = False
try:
    scan_dll = WinDLL(SCAN_DLL_PATH)
    scan_dll.initialize.restype = BOOL
    scan_dll.init_yara_rules.argtypes = [c_char_p]
    scan_dll.init_yara_rules.restype = BOOL
    scan_dll.scan_file.argtypes = [c_char_p]
    scan_dll.scan_file.restype = c_char_p
    scan_dll.calculate_sha256.argtypes = [c_char_p]
    scan_dll.calculate_sha256.restype = c_char_p
    scan_dll.scan_process_memory.argtypes = [c_int]
    scan_dll.scan_process_memory.restype = c_char_p
    scan_dll.free_memory.argtypes = [c_char_p]
    scan_dll.free_memory.restype = None
    scan_dll.cleanup.restype = None
    scan_dll.initialize()
    DLL_LOADED = True
except Exception as e:
    scan_dll = None
    DLL_LOADED = False
    logger.warning(f"Failed to load scan.dll: {e}")
# ================================================

class AntivirusEngine:
    def __init__(self):
        self.scan_count = 0
        self.threats_found = 0
        self.deleted_files = []  # Deletion records
        self.deletion_lock = threading.Lock()
        self.load_deletion_list()
        self._stop_event = threading.Event()
        self.monitor_dir = MONITOR_DIR
        self.quarantine_dir = QUARANTINE_DIR
        self._init_quarantine_dir()
        self.file_integrity_records = {}  # {file_path: (size, mtime, hash)}
        self.integrity_lock = threading.Lock()
        self.api_key = None
        self.yara_support = YARA_SUPPORT
        self.yara_rule = None
        self.dll_loaded = DLL_LOADED
        if self.dll_loaded:
            self._init_dll_yara()
        if self.yara_support:
            try:
                self._load_yara_rule()
            except Exception as e:
                logger.error(f"Failed to load YARA rules: {e}")
                self.yara_rule = None

    def _load_yara_rule(self):
        """Dummy YARA rule loader (not implemented)"""
        # If you want to implement YARA scanning, add code here.
        pass

    def _init_dll_yara(self):
        """初始化 DLL 的 YARA 規則"""
        try:
            yara_rules_text = r'''
import "pe"

rule Suspicious_UEFI_Modification_Improved : pe
{
    meta:
        description = "Detects binaries attempting to modify UEFI firmware or EFI variables"
        author = "wenszeyui"
        version = "2.1"
        date = "2025-07-30"
        reference = "UEFI tampering detection"
        severity = "high"

    strings:
        $efi1 = "SetFirmwareEnvironmentVariableA" wide ascii
        $efi2 = "SetFirmwareEnvironmentVariableW" wide ascii
        $efi3 = "SetFirmwareEnvironmentVariableEx" wide ascii
        $efi4 = "GetFirmwareEnvironmentVariable" wide ascii
        $linux_efi_path = "/sys/firmware/efi/efivars" ascii
        $esp_path = /GLOBALROOT\\Device\\HarddiskVolume[0-9]+\\EFI\\/ wide ascii
        $bootkit_sig = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
        $legit_uefi1 = "UEFI Firmware Update" wide ascii
        $legit_uefi2 = "BIOS Update Utility" wide ascii
    condition:
        pe.is_pe and
        filesize < 5MB and
        any of ($efi*) and
        not any of ($legit_uefi*) and
        (
            any of ($linux_efi_path, $esp_path, $bootkit_sig) or
            (
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableA") or
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableW") or
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableEx") or
                pe.imports("kernel32.dll", "GetFirmwareEnvironmentVariable")
            )
        )
}


rule Detect_File_Encryption_Behavior {
    strings:
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "AES_encrypt" nocase
        $ransom_note = /_decrypt_instructions/i
    condition:
        any of ($crypto*) and $ransom_note
}


rule Detect_File_Extension_Change_Improved : pe
{
    meta:
        description = "Detects binaries that attempt to change file extensions, common in ransomware"
        author = "wennszeyui"
        version = "2.1"
        date = "2025-07-30"
        category = "behavioral"
        maltype = "ransomware or file modifier"
        false_positives = "Some backup utilities may trigger"

    strings:
        // Suspicious extensions
        $ext1 = ".locked" wide ascii
        $ext2 = ".encrypted" wide ascii
        $ext3 = ".enc" wide ascii
        $ext4 = ".pay" wide ascii
        $ext5 = ".deadbolt" wide ascii
        $ext6 = ".crypted" wide ascii
        $ext7 = ".xyz" wide ascii

        // Rename APIs
        $rename1 = "MoveFileA" wide ascii
        $rename2 = "MoveFileW" wide ascii
        $rename3 = "MoveFileExA" wide ascii
        $rename4 = "MoveFileExW" wide ascii

        // Legitimate backup tools
        $legit_backup1 = "Backup Exec" wide ascii
        $legit_backup2 = "Acronis" wide ascii

    condition:
        pe.is_pe and
        not any of ($legit_backup*) and
        any of ($ext*) and
        any of ($rename*) and
        (
            pe.imports("kernel32.dll", "MoveFileA") or
            pe.imports("kernel32.dll", "MoveFileW") or
            pe.imports("kernel32.dll", "MoveFileExA") or
            pe.imports("kernel32.dll", "MoveFileExW")
        )
}


rule Detect_File_Infection_Improved
{
    meta:
        description = "Detects file infectors that append or inject malicious code into PE executables"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "file-infector"
        maltype = "virus"

    strings:
        $marker1 = "INFECTED_BY_SZ" nocase
        $marker2 = "VIRUS_PAYLOAD" nocase
        $marker3 = { E8 ?? ?? ?? ?? 5B 81 EB }
        $marker4 = { 60 E8 ?? ?? ?? ?? 61 }

    condition:
        pe.is_pe and
        (any of ($marker*) or
         pe.entry_point > pe.sections[pe.number_of_sections - 1].virtual_address)
}


rule Detect_Deletion_of_Critical_C_Drive_Files_Improved
{
    meta:
        description = "Detects attempts to delete critical system files on C:\\ drive"
        author = "szeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "destructive"
        maltype = "wiper / ransomware"

    strings:
        // Deletion APIs
        $delete1 = "DeleteFileA"
        $delete2 = "DeleteFileW"
        $delete3 = "SHFileOperation"
        $delete4 = "RemoveDirectoryA"
        $delete5 = "RemoveDirectoryW"

        // Critical system paths (regex for flexibility)
        $sys1 = /[Cc]:\\\\Windows\\\\System32\\\\ntoskrnl\.exe/
        $sys2 = /[Cc]:\\\\Windows\\\\System32\\\\winload\.exe/
        $sys3 = /[Cc]:\\\\Windows\\\\System32\\\\config\\\\SAM/
        $sys4 = /[Cc]:\\\\Windows\\\\System32\\\\drivers\\\\/
        $sys5 = /[Cc]:\\\\boot\.ini/
        $sys6 = /[Cc]:\\\\Windows\\\\explorer\.exe/
        $sys7 = /[Cc]:\\\\Windows\\\\System32\\\\hal\.dll/

    condition:
        pe.is_pe and
        any of ($delete*) and any of ($sys*)
}

rule Detect_Chat_Log_Stealer_Trojan_With_Facebook_Improved
{
    meta:
        description = "Detects trojans that attempt to steal chat logs from messaging apps including Facebook"
        author = "szeyui"
        version = "1.2"
        date = "2025-07-04"
        category = "infostealer"
        maltype = "chat log stealer"

    strings:
        // Messaging platforms
        $discord = "Discord\\Local Storage\\leveldb"
        $telegram = "Telegram Desktop\\tdata"
        $whatsapp = "WhatsApp\\User Data"
        $skype = "Skype\\My Skype Received Files"
        $wechat = "WeChat Files"
        $qq = "Tencent\\QQ"
        $facebook1 = "Facebook\\Messenger"
        $facebook2 = "messenger.com"
        $facebook3 = "messages/inbox"
        $facebook4 = "threads"

        // Chat content
        $chat1 = "chatlog"
        $chat2 = "message history"
        $chat3 = "conversation"
        $chat4 = "msgstore.db"
        $chat5 = "sqlite3_open"

        // Exfiltration
        $exfil1 = "WinHttpSendRequest"
        $exfil2 = "InternetOpenUrl"
        $exfil3 = "curl"
        $exfil4 = "ftp://"
        $exfil5 = "POST /upload"

        // Decryption / encoding
        $crypto1 = "CryptUnprotectData"
        $crypto2 = "Base64Decode"

    condition:
        pe.is_pe and
        (any of ($discord, $telegram, $whatsapp, $skype, $wechat, $qq, $facebook*)) and
        any of ($chat*) and
        any of ($exfil*) and
        any of ($crypto*)
}

rule Detect_Webcam_Spy_Trojan_Improved
{
    meta:
        description = "Detects trojans that attempt to access, record, and exfiltrate webcam footage"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "spyware"
        maltype = "webcam stealer"

    strings:
        // Webcam access
        $cam1 = "capCreateCaptureWindowA"
        $cam2 = "capCreateCaptureWindowW"
        $cam3 = "capDriverConnect"
        $cam4 = "capGrabFrame"
        $cam5 = "capFileSaveAs"
        $cam6 = "avicap32.dll"
        $cam7 = "mf.dll"
        $cam8 = "DirectShow"
        $cam9 = "MediaCapture"
        $cam10 = "Windows.Media.Capture"

        // Device identifiers
        $dev1 = "\\\\.\\Global\\usbvideo"
        $dev2 = "vid_"
        $dev3 = "device\\video"
        $dev4 = "CameraCaptureUI"

        // Output formats
        $ext1 = ".avi"
        $ext2 = ".mp4"
        $ext3 = ".jpg"
        $ext4 = ".bmp"
        $ext5 = "webcam_capture"

        // Exfiltration
        $exfil1 = "WinHttpSendRequest"
        $exfil2 = "InternetOpenUrl"
        $exfil3 = "POST /upload"
        $exfil4 = "ftp://"
        $exfil5 = "http://"

    condition:
        pe.is_pe and
        (any of ($cam*) or any of ($dev*)) and
        any of ($ext*) and
        any of ($exfil*)
}


rule Detect_MBR_Modification_Improved
{
    meta:
        description = "Detects binaries attempting to modify the Master Boot Record (MBR)"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-05"
        category = "bootkit"
        maltype = "MBR modifier"

    strings:
        // API functions
        $api1 = "CreateFileA" nocase
        $api2 = "CreateFileW" nocase
        $api3 = "WriteFile" nocase
        $api4 = "DeviceIoControl" nocase
        $api5 = "ReadFile" nocase
        $api6 = "SetFilePointer" nocase

        // Disk access targets
        $disk = /\\\\\.\\(PhysicalDrive|C)([0-9]*)?/ nocase

        // Known malicious MBR patterns
        $bootkit1 = { B8 00 7C 8E D8 8E C0 BE 00 7C BF 00 06 B9 00 02 F3 A5 }
        $bootkit2 = { FA 33 C0 8E D0 BC 00 7C FB 8E D8 E8 00 00 }

    condition:
        pe.is_pe and (
            (any of ($api*) and $disk) or
            (uint16(0x1FE) == 0xAA55 and any of ($bootkit*))
        )
}


rule Detect_GPT_Partition_Modification_Improved
{
    meta:
        description = "Detects binaries attempting to modify GPT partition tables"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-05"
        category = "bootkit / persistence"
        maltype = "GPT modifier"

    strings:
        // API functions
        $api1 = "CreateFileA" nocase
        $api2 = "CreateFileW" nocase
        $api3 = "WriteFile" nocase
        $api4 = "DeviceIoControl" nocase
        $api5 = "ReadFile" nocase

        // Disk access targets
        $disk = /\\\\\.\\(PhysicalDrive|Harddisk)[0-9]+(\\Partition[0-9]+)?/ nocase

        // GPT header signature
        $gpt_sig = { 45 46 49 20 50 41 52 54 }  // "EFI PART"

        // Known GUIDs
        $guid1 = { 28 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B }  // EFI System Partition
        $guid2 = { A2 A0 D0 EB E5 B9 33 44 87 C0 68 B6 B7 26 99 C7 }  // Microsoft Reserved

    condition:
        pe.is_pe and
        (any of ($api*) and $disk) and
        (any of ($gpt_sig, $guid1, $guid2))
}


rule Suspicious_JS_Downloader_Improved
{
    meta:
        description = "Detects JavaScript files that download and execute payloads"
        author = "wenszeyui"
        category = "script"
        maltype = "downloader"

    strings:
        // Download behavior
        $url = /https?:\/\/[^\s"]+/ nocase
        $xmlhttp1 = "MSXML2.XMLHTTP" nocase
        $xmlhttp2 = "XMLHttpRequest" nocase
        $stream = "ADODB.Stream" nocase

        // Execution behavior
        $eval = "eval(" nocase
        $wscript = "WScript.Shell" nocase
        $run = ".Run(" nocase
        $powershell = "powershell -" nocase

        // Obfuscation
        $obf1 = "String.fromCharCode" nocase
        $obf2 = "unescape(" nocase

        // File writing
        $write1 = "SaveToFile" nocase
        $write2 = "CreateTextFile" nocase

    condition:
        filesize < 100KB and
        (1 of ($url, $xmlhttp1, $xmlhttp2, $stream, $powershell)) and
        (any of ($eval, $wscript, $run)) and
        (any of ($write1, $write2) or any of ($obf1, $obf2))
}
rule Detect_Script_Persistence_Improved
{
    meta:
        description = "Detects scripts attempting to establish persistence via registry, tasks, or startup folder"
        author = "wenszeyui"
        category = "script"
        maltype = "persistence"

    strings:
        $reg1 = "reg add" nocase
        $reg2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $schtasks = "schtasks /create" nocase
        $startup = "\\Startup\\" nocase
        $wmi = "__EventFilter" nocase
        $profile = "Microsoft.PowerShell_profile.ps1" nocase

    condition:
        filesize < 100KB and
        (2 of ($reg*, $schtasks, $startup, $wmi, $profile))
}
rule Detect_Script_UEFI_Modification_Improved
{
    meta:
        description = "Detects scripts attempting to modify UEFI firmware or EFI variables"
        author = "szeyui"
        category = "script / firmware"
        maltype = "UEFI tampering"

    strings:
        $wmi = "GetObject(\"winmgmts:" nocase
        $bios = "Win32_BIOS" nocase
        $firmware1 = "SetFirmwareEnvironmentVariable" nocase
        $firmware2 = "SetFirmwareEnvironmentVariableEx" nocase
        $firmware3 = "GetFirmwareEnvironmentVariable" nocase
        $ps = "powershell.exe" nocase
        $efi1 = "\\EFI\\" nocase
        $efi2 = "GLOBALROOT\\Device\\HarddiskVolume" nocase

    condition:
        filesize < 100KB and
        any of ($wmi, $bios, $firmware1, $firmware2, $firmware3, $ps) and
        any of ($efi1, $efi2)
}
rule Detect_Browser_Password_Stealer_Improved
{
    meta:
        description = "Detects attempts to steal and exfiltrate browser passwords"
        author = "szeyui"
        category = "infostealer"
        maltype = "browser stealer"

    strings:
        // Browser password storage
        $chrome = "Chrome\\User Data\\Default\\Login Data"
        $firefox = "signons.sqlite"
        $edge = "Microsoft\\Edge\\User Data"
        $brave = "BraveSoftware\\Brave-Browser\\User Data"
        $opera = "Opera Software\\Opera Stable"

        // Exfiltration
        $exfil1 = "POST /upload"
        $exfil2 = "WinHttpSendRequest"
        $exfil3 = "HttpSendRequest"
        $exfil4 = "InternetOpenUrl"

        // Decryption
        $decrypt = "CryptUnprotectData"

    condition:
        pe.is_pe and
        any of ($chrome, $firefox, $edge, $brave, $opera) and
        any of ($exfil1, $exfil2, $exfil3, $exfil4) and
        $decrypt
}

rule Detect_EFI_Driver_Load_Improved
{
    meta:
        description = "Detects potential EFI driver loading behavior"
        author = "szeyui"
        category = "bootkit"
        maltype = "efi loader"

    strings:
        $efi1 = "\\EFI\\Boot\\bootx64.efi"
        $efi2 = "LoadImage"
        $efi3 = "StartImage"
        $efi4 = "HandleProtocol"
        $efi5 = "InstallProtocolInterface"
        $sig = { 45 46 49 20 50 41 52 54 } // "EFI PART"

    condition:
        // FIX: remove pe.is_64bit, use only pe.machine == pe.MACHINE_AMD64
        (pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
         2 of ($efi*)) or $sig
}

rule Detect_DLL_Injector_Improved
{
    meta:
        description = "Detects potential DLL injection behavior in PE files"
        author = "szeyui"
        category = "trojan"
        maltype = "injector"

    strings:
        $api1 = "OpenProcess"
        $api2 = "VirtualAllocEx"
        $api3 = "WriteProcessMemory"
        $api4 = "CreateRemoteThread"
        $api5 = "LoadLibraryA"
        $api6 = "LoadLibraryW"
        $dll = /\.dll/i

    condition:
        pe.is_pe and
        4 of ($api*) and $dll
}

rule VBScript_FileInfector_SZ_Improved
{
    meta:
        description = "Detects VBScript virus with file infection, destructive behavior, and obfuscation"
        author = "szeyui"
        version = "1.1"
        date = "2025-07-17"
        category = "virus"
        maltype = "vbscript file infector"

    strings:
        // Infection and replication
        $copy1 = "CreateObject(\"Scripting.FileSystemObject\")"
        $copy2 = "CopyFile WScript.ScriptFullName"
        $copy3 = "GetSpecialFolder"
        $copy4 = "WScript.ScriptFullName"

        // Destructive behavior
        $del1 = /Delete(File|Folder)\s+"C:\\\\.*"/
        $del2 = "SetAttr"

        // Dynamic execution / obfuscation
        $exec1 = "Execute("
        $exec2 = "Eval("
        $exec3 = "Chr("
        $exec4 = "Base64Decode"

        // Marker or payload
        $marker = "INFECTED_BY_SZ"

    condition:
        any of ($copy*) and any of ($del*) and any of ($exec*) and $marker
}

rule Detect_Process_Injection_Improved
{
    meta:
        description = "Detects potential process injection behavior in PE files"
        author = "wenszeyui"
        category = "trojan"
        maltype = "process injector"

    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "NtCreateThreadEx"
        $api3 = "WriteProcessMemory"
        $api4 = "VirtualAllocEx"
        $api5 = "QueueUserAPC"
        $api6 = "SetWindowsHookEx"

    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "WriteProcessMemory") or
        pe.imports("kernel32.dll", "CreateRemoteThread") or
        pe.imports("ntdll.dll", "NtCreateThreadEx") or
        3 of ($api*)
}


rule Detect_Self_Modifying_Code_Improved
{
    meta:
        description = "Detects potential self-modifying code behavior in PE files"
        author = "wenszeyui"
        category = "malware"
        maltype = "self-modifying code"

    strings:
        $api1 = "VirtualProtect"
        $api2 = "VirtualAlloc"
        $api3 = "WriteProcessMemory"
        $api4 = "FlushInstructionCache"

    condition:
        pe.is_pe and
        (pe.imports("kernel32.dll", "VirtualProtect") and
         pe.imports("kernel32.dll", "VirtualAlloc") and
         pe.imports("kernel32.dll", "WriteProcessMemory") and
         pe.imports("kernel32.dll", "FlushInstructionCache")) or
        all of ($api*)
}

'''
            scan_dll.init_yara_rules(yara_rules_text.encode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to init DLL YARA rules: {e}")

    def _init_quarantine_dir(self):
        """创建安全的隔离区目录"""
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir)
            
            # 设置隔离区权限：只有SYSTEM和Administrators可以访问
            self._set_secure_permissions(self.quarantine_dir)
            logger.info(f"Quarantine directory initialized at {self.quarantine_dir}")
        except Exception as e:
            logger.error(f"Failed to initialize quarantine directory: {e}")

    def _set_secure_permissions(self, path):
        """设置路径的安全权限 - 只允许SYSTEM和Administrators访问"""
        try:
            # 获取当前的安全描述符
            sd = win32security.GetFileSecurity(
                path, 
                win32security.DACL_SECURITY_INFORMATION
            )
        
            # 建立新的 DACL
            dacl = win32security.ACL()
        
            # 添加 SYSTEM 完全控制
            system_sid = win32security.CreateWellKnownSid(
                win32security.WinLocalSystemSid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, 
                con.FILE_ALL_ACCESS, 
                system_sid
            )
        
            # 添加 Administrators 完全控制
            admin_sid = win32security.CreateWellKnownSid(
                win32security.WinBuiltinAdministratorsSid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, 
                con.FILE_ALL_ACCESS, 
                admin_sid
            )
        
            # 移除所有繼承的 ACE
            sd.SetSecurityDescriptorControl(
                win32security.SE_DACL_PROTECTED, 
                win32security.SE_DACL_PROTECTED
            )
        
            # 設定新的 DACL
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                path, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
            logger.info(f"設定安全權限: {path}")
            return True
        except Exception as e:
            logger.error(f"設定安全權限失敗: {e}")
            return False
       
        

    def quarantine_file(self, file_path, reason):
        """将文件移动到隔离区（优先用DLL）"""
        if self.dll_loaded and scan_dll:
            try:
                c_file = file_path.encode('utf-8')
                c_dir = self.quarantine_dir.encode('utf-8')
                result = scan_dll.quarantine_file(c_file, c_dir)
                if result:
                    logger.info(f"Successfully quarantined file (DLL): {file_path}")
                    # 记录隔离操作（可选，略）
                    return True
            except Exception as e:
                logger.error(f"DLL quarantine error: {file_path} - {e}")
        # fallback: 原有Python实现
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File not found for quarantine: {file_path}")
                return False
                
            # 生成唯一的隔离文件名
            filename = os.path.basename(file_path)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            base, ext = os.path.splitext(filename)
            quarantine_filename = f"{base}_{timestamp}{ext}"
            dest_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # 移动文件到隔离区
            shutil.move(file_path, dest_path)
            
            # 设置隔离文件的权限
            self._set_secure_permissions(dest_path)
            
            # 记录隔离操作
            record = {
                "original_path": file_path,
                "quarantine_path": dest_path,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "quarantined": True
            }
            
            with self.deletion_lock:
                self.deleted_files.append(record)
                self.save_deletion_list()
            
            logger.info(f"Successfully quarantined file: {file_path} -> {dest_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False

    def delete_file(self, file_path, reason=None):
        """删除文件（优先用DLL）"""
        if self.dll_loaded and scan_dll:
            try:
                c_file = file_path.encode('utf-8')
                result = scan_dll.delete_file(c_file)
                if result:
                    logger.info(f"Successfully deleted file (DLL): {file_path}")
                    # 记录删除操作（可选，略）
                    return True
            except Exception as e:
                logger.error(f"DLL delete error: {file_path} - {e}")
        # fallback: 原有Python实现
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File not found for deletion: {file_path}")
                return False
            
            os.remove(file_path)
            logger.info(f"Successfully deleted file: {file_path}")
            
            # 记录删除操作
            if reason:
                logger.info(f"Deletion reason: {reason}")
            
            # 更新记录
            with self.deletion_lock:
                self.deleted_files = [r for r in self.deleted_files 
                                     if r.get("original_path") != file_path]
                self.save_deletion_list()
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete file {file_path}: {e}")
            return False

    def restore_quarantined_file(self, quarantine_path, original_path=None):
        """从隔离区恢复文件"""
        try:
            if not os.path.exists(quarantine_path):
                logger.warning(f"Quarantined file not found: {quarantine_path}")
                return False
                
            # 如果未提供原始路径，则使用记录中的路径
            if not original_path:
                for record in self.deleted_files:
                    if record.get("quarantine_path") == quarantine_path:
                        original_path = record.get("original_path")
                        break
                
                if not original_path:
                    logger.error(f"Original path not found for quarantined file: {quarantine_path}")
                    return False
            
            # 恢复文件
            shutil.move(quarantine_path, original_path)
            
            # 更新记录
            with self.deletion_lock:
                self.deleted_files = [r for r in self.deleted_files 
                                     if r.get("quarantine_path") != quarantine_path]
                self.save_deletion_list()
            
            logger.info(f"Successfully restored file: {quarantine_path} -> {original_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore quarantined file {quarantine_path}: {e}")
            return False
    
    
    def is_whitelisted(self, file_path):
        """Check if file is in whitelisted SHA256 hash list"""
        try:
            file_hash = self.calculate_sha256(file_path)
            if file_hash and file_hash.lower() in [h.lower() for h in WHITELISTED_HASHES]:
                return True
            return False
        except Exception as e:
            logger.error(f"Error checking whitelist for {file_path}: {e}")
            return False
    
    def stop(self):
        """Stop all scanning"""
        self._stop_event.set()
        logger.info("Antivirus engine stopped")
    
    def load_deletion_list(self):
        """Load deletion records"""
        deletion_file = os.path.join(DELETION_LOG_DIR, "deletion_log.json")
        if os.path.exists(deletion_file):
            try:
                with open(deletion_file, 'r', encoding='utf-8') as f:
                    self.deleted_files = json.load(f)
                logger.info(f"Successfully loaded deletion records, total {len(self.deleted_files)} files")
            except Exception as e:
                logger.error(f"Failed to load deletion records: {e}")
                self.deleted_files = []
    
    def save_deletion_list(self):
        """Save deletion records"""
        deletion_file = os.path.join(DELETION_LOG_DIR, "deletion_log.json")
        with self.deletion_lock:
            try:
                with open(deletion_file, 'w', encoding='utf-8') as f:
                    json.dump(self.deleted_files, f, indent=2, ensure_ascii=False)
                logger.info("Deletion records saved successfully")
            except Exception as e:
                logger.error(f"Failed to save deletion records: {e}")
    
    def scan_file(self, file_path):
        """Scan single file"""
        self.scan_count += 1

        if self._stop_event.is_set():
            return "Scan stopped", 0

        if not os.path.exists(file_path):
            return "File does not exist", 0

        if self.is_whitelisted(file_path):
            return "Whitelisted file", 0

        # Sandbox scan first
        sandbox_matched, sandbox_rule_names = self.sandbox_scan_file(file_path)
        if sandbox_matched:
            self.threats_found += 1
            return f"Sandbox match: {', '.join(sandbox_rule_names)}", 100

        # YARA scan for any rule match
        yara_matched, yara_rule_names = self.yara_scan_file(file_path)
        if yara_matched:
            self.threats_found += 1
            return f"YARA match: {', '.join(yara_rule_names)}", 100

        # File extension risk assessment
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Initial risk assessment
        if ext in ['.exe', '.bat', '.cmd', '.vbs', '.js', '.jar', '.dll', '.sys']:
            result = "High risk file type"
            score = 30
        else:
            result = "Safe"
            score = 0

        # Heuristic analysis
        suspicious_score = 0
        if suspicious_score > 50:
            score = max(score, suspicious_score)
            result = f"Suspicious file (score: {suspicious_score})"
        
        if score > 70:
            self.threats_found += 1
        
        return result, score
    
    def calculate_sha256(self, file_path):
        """Calculate SHA256 hash of file (DLL優先)"""
        if self.dll_loaded and scan_dll:
            try:
                c_path = file_path.encode('utf-8')
                result = scan_dll.calculate_sha256(c_path)
                if result:
                    hash_str = ctypes.string_at(result).decode('utf-8')
                    scan_dll.free_memory(result)
                    return hash_str
            except Exception as e:
                logger.error(f"DLL SHA256 error: {file_path} - {e}")
        # fallback
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating SHA256 hash: {file_path} - {e}")
            return None
# ================================================

class AntivirusGUI:
    def __init__(self, engine):
        self.engine = engine
        self.root = tk.Tk()
        self.root.title("Windows Defender - Antivirus")
        self.root.geometry("900x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#f3f6fb")
        self._setup_style()
        self._build_interface()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _setup_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TNotebook", background="#f3f6fb", borderwidth=0)
        style.configure("TNotebook.Tab", background="#e5eaf3", font=("Segoe UI", 11, "bold"), padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "#0078d7")], foreground=[("selected", "#fff")])
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TLabel", background="#f3f6fb", font=("Segoe UI", 10))
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=28, background="#fff", fieldbackground="#fff")
        style.configure("TEntry", font=("Segoe UI", 10))

    def _build_interface(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Scan Tab
        scan_tab = ttk.Frame(notebook)
        self._build_scan_tab(scan_tab)
        notebook.add(scan_tab, text="Scan")

        # Quarantine Tab
        quarantine_tab = ttk.Frame(notebook)
        self._build_quarantine_tab(quarantine_tab)
        notebook.add(quarantine_tab, text="Quarantine")

        # Deletion Log Tab
        log_tab = ttk.Frame(notebook)
        self._build_log_tab(log_tab)
        notebook.add(log_tab, text="Deletion Log")

        # Junk Cleaner Tab
        junk_tab = ttk.Frame(notebook)
        self._build_junk_tab(junk_tab)
        notebook.add(junk_tab, text="Junk Cleaner")

    def _build_scan_tab(self, tab):
        lbl = ttk.Label(tab, text="Scan a file or folder for threats", font=("Segoe UI", 12, "bold"))
        lbl.pack(pady=10)
        frame = ttk.Frame(tab)
        frame.pack(pady=10)
        self.scan_path_var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self.scan_path_var, width=60)
        entry.pack(side="left", padx=5)
        btn_file = ttk.Button(frame, text="Browse File", command=self._browse_file)
        btn_file.pack(side="left", padx=5)
        btn_folder = ttk.Button(frame, text="Browse Folder", command=self._browse_folder)
        btn_folder.pack(side="left", padx=5)
        btn_scan = ttk.Button(frame, text="Scan", command=self._scan_selected)
        btn_scan.pack(side="left", padx=5)
        self.scan_result_text = scrolledtext.ScrolledText(tab, height=15, font=("Segoe UI", 10), bg="#fff")
        self.scan_result_text.pack(fill="both", expand=True, padx=10, pady=10)

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select file to scan")
        if path:
            self.scan_path_var.set(path)

    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            self.scan_path_var.set(path)

    def _scan_selected(self):
        path = self.scan_path_var.get()
        self.scan_result_text.delete(1.0, tk.END)
        if not path:
            self.scan_result_text.insert(tk.END, "Please select a file or folder.\n")
            return
        if os.path.isfile(path):
            result, score = self.engine.scan_file(path)
            self.scan_result_text.insert(tk.END, f"File: {path}\nResult: {result}\nRisk Score: {score}\n")
        elif os.path.isdir(path):
            self.scan_result_text.insert(tk.END, f"Scanning folder: {path}\n")
            for root, dirs, files in os.walk(path):
                for f in files:
                    fpath = os.path.join(root, f)
                    result, score = self.engine.scan_file(fpath)
                    self.scan_result_text.insert(tk.END, f"{fpath}\nResult: {result}\nRisk Score: {score}\n")
        else:
            self.scan_result_text.insert(tk.END, "Invalid path.\n")

    def _build_quarantine_tab(self, tab):
        lbl = ttk.Label(tab, text="Quarantine Area", font=("Segoe UI", 12, "bold"))
        lbl.pack(pady=10)
        self.quarantine_tree = ttk.Treeview(tab, columns=("original", "reason", "timestamp"), show="headings")
        self.quarantine_tree.heading("original", text="Original Path")
        self.quarantine_tree.heading("reason", text="Reason")
        self.quarantine_tree.heading("timestamp", text="Timestamp")
        self.quarantine_tree.pack(fill="both", expand=True, padx=10, pady=10)
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(pady=5)
        btn_restore = ttk.Button(btn_frame, text="Restore", command=self._restore_quarantined)
        btn_restore.pack(side="left", padx=5)
        btn_delete = ttk.Button(btn_frame, text="Delete", command=self._delete_quarantined)
        btn_delete.pack(side="left", padx=5)
        self._refresh_quarantine()

    def _refresh_quarantine(self):
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        for record in self.engine.deleted_files:
            if record.get("quarantined"):
                self.quarantine_tree.insert("", "end", values=(
                    record.get("original_path"),
                    record.get("reason"),
                    record.get("timestamp"),
                ))

    def _restore_quarantined(self):
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo("Restore", "Please select a quarantined file to restore.")
            return
        item = self.quarantine_tree.item(selected[0])
        quarantine_path = None
        for record in self.engine.deleted_files:
            if record.get("original_path") == item["values"][0] and record.get("quarantined"):
                quarantine_path = record.get("quarantine_path")
                break
        if quarantine_path and self.engine.restore_quarantined_file(quarantine_path):
            messagebox.showinfo("Restore", "File restored successfully.")
            self._refresh_quarantine()
        else:
            messagebox.showerror("Restore", "Failed to restore file.")

    def _delete_quarantined(self):
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo("Delete", "Please select a quarantined file to delete.")
            return
        item = self.quarantine_tree.item(selected[0])
        quarantine_path = None
        for record in self.engine.deleted_files:
            if record.get("original_path") == item["values"][0] and record.get("quarantined"):
                quarantine_path = record.get("quarantine_path")
                break
        if quarantine_path and self.engine.delete_file(quarantine_path, reason="Manual delete from quarantine"):
            messagebox.showinfo("Delete", "File deleted successfully.")
            self._refresh_quarantine()
        else:
            messagebox.showerror("Delete", "Failed to delete file.")

    def _build_log_tab(self, tab):
        lbl = ttk.Label(tab, text="Deletion Log", font=("Segoe UI", 12, "bold"))
        lbl.pack(pady=10)
        self.log_tree = ttk.Treeview(tab, columns=("original", "reason", "timestamp"), show="headings")
        self.log_tree.heading("original", text="Original Path")
        self.log_tree.heading("reason", text="Reason")
        self.log_tree.heading("timestamp", text="Timestamp")
        self.log_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._refresh_log()

    def _refresh_log(self):
        self.log_tree.delete(*self.log_tree.get_children())
        for record in self.engine.deleted_files:
            if not record.get("quarantined"):
                self.log_tree.insert("", "end", values=(
                    record.get("original_path"),
                    record.get("reason"),
                    record.get("timestamp"),
                ))

    def _build_junk_tab(self, tab):
        lbl = ttk.Label(tab, text="Junk Cleaner", font=("Segoe UI", 12, "bold"))
        lbl.pack(pady=10)
        frame = ttk.Frame(tab)
        frame.pack(pady=10)
        btn_scan = ttk.Button(frame, text="Scan for Junk", command=self._scan_junk)
        btn_scan.pack(side="left", padx=5)
        btn_clean = ttk.Button(frame, text="Clean Junk", command=self._clean_junk)
        btn_clean.pack(side="left", padx=5)
        self.junk_result_text = scrolledtext.ScrolledText(tab, height=15, font=("Segoe UI", 10), bg="#fff")
        self.junk_result_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.junk_files = []

    def _scan_junk(self):
        self.junk_result_text.delete(1.0, tk.END)
        self.junk_files = []
        # Common junk locations
        junk_dirs = [
            os.environ.get("TEMP", ""),
            os.path.expanduser("~\\AppData\\Local\\Temp"),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\INetCache"),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files"),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\Explorer"),
            os.path.expanduser("~\\AppData\\Local\\CrashDumps"),
        ]
        for d in junk_dirs:
            if os.path.exists(d):
                for root, dirs, files in os.walk(d):
                    for f in files:
                        fpath = os.path.join(root, f)
                        self.junk_files.append(fpath)
        self.junk_result_text.insert(tk.END, f"Found {len(self.junk_files)} junk files.\n")
        for f in self.junk_files[:100]:
            self.junk_result_text.insert(tk.END, f"{f}\n")
        if len(self.junk_files) > 100:
            self.junk_result_text.insert(tk.END, f"...and {len(self.junk_files) - 100} more.\n")

    def _clean_junk(self):
        count = 0
        for f in self.junk_files:
            try:
                os.remove(f)
                count += 1
            except Exception:
                pass
        self.junk_result_text.insert(tk.END, f"\nCleaned {count} junk files.\n")

    def on_close(self):
        self.engine.save_deletion_list()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

# ...existing code...

if __name__ == "__main__":
    print("AntivirusCore starting...")
    engine = AntivirusEngine()
    print(f"DLL loaded: {engine.dll_loaded}")
    print(f"YARA support: {engine.yara_support}")
    
    # 测试扫描当前文件
    test_file = os.path.abspath(__file__)
    result, score = engine.scan_file(test_file)
    print(f"Scan result for {test_file}: {result}, risk score: {score}")
    
    # 启动GUI界面
    print("Launching GUI...")
    gui = AntivirusGUI(engine)
    gui.run()
