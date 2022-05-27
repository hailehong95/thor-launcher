#!/usr/bin/env python3

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from io import BytesIO

import os
import stat
import time
import shlex
import click
import shutil
import random
import string
import zipfile
import logging
import binascii
import platform
import traceback
import subprocess
import PyInstaller.__main__


def get_platform():
    if platform.system().lower() == 'darwin':
        return 'macosx'
    return platform.system().lower()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
THOR_DIR = os.path.join(BASE_DIR, get_platform())
PRODUCT_NAME = 'THOR APT Scanner'
UTILITY_NAME = 'THOR Utility'
UTILITY_VERSION = '1.0'

DIRS_DELETED = {"docs", "threatintel", "tools"}
GENERAL_DELETED = {"changes.log", "thor-lite-util", "thor-lite-util.sig", "thor-lite-util.exe", "thor-lite-util.exe.sig", "thor-util.exe", "thor-util.exe.sig", "thor-util", "thor-util.sig", "orig--thor-lite-util.exe.tmp", "orig--thor-lite-util.tmp"}
FILES_DELETED_WINDOWS_X86 = {"thor-lite.exe", "thor-lite.exe.sig", "thor.exe", "thor.exe.sig"}
FILES_DELETED_WINDOWS_X64 = {"thor64-lite.exe", "thor64-lite.exe.sig", "thor64.exe", "thor64.exe.sig"}
FILES_DELETED_LINUX_X86 = {"thor-lite-linux", "thor-lite-linux.sig", "thor-linux", "thor-linux.sig"}
FILES_DELETED_LINUX_X64 = {"thor-lite-linux-64", "thor-lite-linux-64.sig", "thor-linux-64", "thor-linux-64.sig"}


def unzip_thor_pack(platform, thor_dir):
    try:
        thor_zip_file = ''
        thor_packs_dir = os.path.join(BASE_DIR, "thor_packs")
        list_thor_packs = os.listdir(thor_packs_dir)
        if '.gitignore' in list_thor_packs:
            list_thor_packs.remove('.gitignore')
        if platform == 'windows':
            thor_zip_file = [x for x in list_thor_packs if 'win' in x][0]
        elif platform == 'linux':
            thor_zip_file = [x for x in list_thor_packs if 'linux' in x][0]
        elif platform == 'macosx':
            thor_zip_file = [x for x in list_thor_packs if 'macosx' in x][0]

        if thor_zip_file != '':
            thor_zip_path = os.path.join(thor_packs_dir, thor_zip_file)
            with zipfile.ZipFile(thor_zip_path, 'r') as zip_ref:
                zip_ref.extractall(thor_dir)
        print("[+] Successful unzip THOR pack: {0}".format(os.listdir(thor_dir)))

    except Exception as e:
        logging.error(traceback.format_exc())


def get_files_in_dir(path):
    try:
        if os.path.exists(path):
            files_and_dirs = os.listdir(path)
            files = [x for x in files_and_dirs if os.path.isfile(os.path.join(path, x))]
            return files
    except Exception as e:
        logging.error(traceback.format_exc())


def get_windows_thor_scanner_bin():
    try:
        thor_files = get_files_in_dir(THOR_DIR)
        thor_files_binary = list()
        for x in thor_files:
            win_file = open(os.path.join(THOR_DIR, x), 'rb')
            win_file_hex = binascii.hexlify(win_file.read()[:16]) # Get Header of file.
            if b'4d5a' in win_file_hex:
                thor_files_binary.append(x)
            win_file.close()

        thor_files_binary_not_util = [x for x in thor_files_binary if 'util' not in x]
        return thor_files_binary_not_util
    except Exception as e:
        logging.error(traceback.format_exc())


def get_linux_thor_scanner_bin():
    try:
        thor_files = get_files_in_dir(THOR_DIR)
        thor_files_binary = list()
        for x in thor_files:
            lin_file = open(os.path.join(THOR_DIR, x), 'rb')
            lin_file_hex = binascii.hexlify(lin_file.read()[:16]) # Get Header of file.
            if b'7f454c46' in lin_file_hex:
                thor_files_binary.append(x)
            lin_file.close()

        thor_files_binary_not_util = [x for x in thor_files_binary if 'util' not in x]
        return thor_files_binary_not_util
    except Exception as e:
        logging.error(traceback.format_exc())


def get_macosx_thor_scanner_bin():
    try:
        thor_files = get_files_in_dir(THOR_DIR)
        thor_files_binary = list()
        for x in thor_files:
            mac_file = open(os.path.join(THOR_DIR, x), 'rb')
            mac_file_hex = binascii.hexlify(mac_file.read()[:16]) # Get Header of file.
            if b'cffaedfe' in mac_file_hex:
                thor_files_binary.append(x)
            mac_file.close()

        thor_files_binary_not_util = [x for x in thor_files_binary if 'util' not in x]
        return thor_files_binary_not_util
    except Exception as e:
        logging.error(traceback.format_exc())


def get_thor_scanner_bin():
    try:
        os_platform = get_platform()
        if os_platform == 'windows':
            win_thor_scanner = get_windows_thor_scanner_bin()
            return win_thor_scanner[0]
        elif os_platform == 'linux':
            lin_thor_scanner = get_linux_thor_scanner_bin()
            return lin_thor_scanner[0]
        elif os_platform == 'macosx':
            mac_thor_scanner = get_macosx_thor_scanner_bin()
            return mac_thor_scanner[0]
        else:
            return 'unknown'
    except Exception as e:
        logging.error(traceback.format_exc())


def get_thor_util_bin():
    try:
        thor_files = get_files_in_dir(THOR_DIR)
        thor_files_not_sig = [x for x in thor_files if '.sig' not in x]
        thor_util_binary = [x for x in thor_files_not_sig if '-util' in x][0]
        if os.path.isfile(os.path.join(THOR_DIR, thor_util_binary)):
            return thor_util_binary
        else:
            return ''
    except Exception as e:
        logging.error(traceback.format_exc())


def grant_execute_permission():
    try:
        os_platform = get_platform()
        if os_platform != 'windows':
            thor_util_bin = get_thor_util_bin()
            thor_util_bin = os.path.join(THOR_DIR, thor_util_bin)
            st = os.stat(thor_util_bin)
            os.chmod(thor_util_bin, st.st_mode | stat.S_IEXEC)

            thor_scanner_bin = get_thor_scanner_bin()
            thor_scanner_bin = os.path.join(THOR_DIR, thor_scanner_bin)
            st = os.stat(thor_scanner_bin)
            os.chmod(thor_scanner_bin, st.st_mode | stat.S_IEXEC)

    except Exception as e:
        logging.error(traceback.format_exc())


def get_file_recursive(path, ext):
    sig_files = list()
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(ext):
                sig_files.append(os.path.join(root, file))
    return sig_files


def secure_string_random(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def generate_rsa_keys(name, length):
    try:
        new_key = RSA.generate(int(length))
        private_key = new_key.exportKey()
        public_key = new_key.publickey().exportKey()
        with open(os.path.join(BASE_DIR, 'rsa_keys', name + '.pri'), 'wb') as f:
            f.write(private_key)
        with open(os.path.join(BASE_DIR, 'rsa_keys', name + '.pub'), 'wb') as f:
            f.write(public_key)

    except Exception as e:
        logging.error(traceback.format_exc())


def extract_task():
    try:
        print("[*] Extracting THOR Pack.")
        os.chdir(BASE_DIR)
        os_platform = get_platform()
        print("[+] Platform is: {0}".format(os_platform))
        print("[+] Creating \'{0}\' directory".format(os_platform))
        if not os.path.exists(THOR_DIR):
            os.mkdir(THOR_DIR)
        print("[+] THOR directory: \'{0}\'".format(THOR_DIR))
        unzip_thor_pack(os_platform, THOR_DIR)
        grant_execute_permission()
        print("[+] Granted execute permission for THOR binaries.\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())


def license_task():
    try:
        print("[*] Adding THOR License")
        os.chdir(BASE_DIR)
        list_license_file = os.listdir('thor_license')
        if '.gitignore' in list_license_file:
            list_license_file.remove('.gitignore')
        print("[+] Checking THOR License: Total {0} license files {1}".format(len(list_license_file), list_license_file))
        license_file_path = os.path.join(BASE_DIR, 'thor_license', list_license_file[0])
        if os.path.isfile(license_file_path) and os.path.exists(THOR_DIR):
            shutil.copyfile(license_file_path, os.path.join(THOR_DIR, 'hailh-license.lic'))
        if os.path.isfile(os.path.join(THOR_DIR, 'hailh-license.lic')):
            print("[+] Successful add THOR license\n")
        else:
            print("[-] Failed to add THOR license\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())


def rsa_key_task():
    try:
        print("[*] Adding encryption key")
        os.chdir(BASE_DIR)
        rsa_pub_key_file = list()
        rsa_key_files = os.listdir('rsa_keys')
        if '.gitignore' in rsa_key_files:
            rsa_key_files.remove('.gitignore')
        for x in rsa_key_files:
            key_file = open(os.path.join(BASE_DIR, 'rsa_keys', x), 'r')
            if 'PUBLIC KEY-----' in key_file.read():
                rsa_pub_key_file.append(x)
            key_file.close()
        
        print("[+] Total {0} encryption keys {1}".format(len(rsa_pub_key_file), rsa_pub_key_file))
        rsa_pub_key_file_path = os.path.join(BASE_DIR, 'rsa_keys', rsa_pub_key_file[0])
        if os.path.isfile(rsa_pub_key_file_path) and os.path.exists(THOR_DIR):
            shutil.copyfile(rsa_pub_key_file_path, os.path.join(THOR_DIR, 'hailh-rsa-public.pem'))
        if os.path.isfile(os.path.join(THOR_DIR, 'hailh-rsa-public.pem')):
            print("[+] Successful add encryption key\n")
        else:
            print("[-] Failed to add encryption key\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())


def signature_task():
    try:
        print("[*] Adding custom signatures")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to Add custom signatures\n")
            return
        
        list_yar_files = get_file_recursive(os.path.join(BASE_DIR, 'signatures'), '.yar')
        list_yara_files = get_file_recursive(os.path.join(BASE_DIR, 'signatures'), '.yara')
        list_signature_file = list_yar_files + list_yara_files
        print("[+] Checking custom signatures: Total {0} file {1}".format(len(list_signature_file), [os.path.basename(x) for x in list_signature_file]))
        thor_util_binary = get_thor_util_bin()
        if os.path.isfile(thor_util_binary) and len(list_signature_file) > 0:
            strCmdEncrypt = list()
            if get_platform() == 'windows':
                strCmdEncrypt.append(thor_util_binary)
            else:
                strCmdEncrypt.append('./' + thor_util_binary)

            strCmdEncrypt.append('encrypt')
            strCmdEncrypt = strCmdEncrypt + list_signature_file
            print("[+] Starting encrypt signature files")
            strCmdEncryptOutput = subprocess.run(strCmdEncrypt, stdout=subprocess.PIPE)
            list_yas_files = get_file_recursive(os.path.join(BASE_DIR, 'signatures'), '.yas')
            if len(list_yas_files) >= 1:
                print("[+] Total {0} signature files encrypted: {1}".format(len(list_yas_files), [os.path.basename(x) for x in list_yas_files]))
                for x in list_yas_files:
                    if os.path.isfile(x):
                        shutil.copyfile(x, os.path.join(THOR_DIR, 'custom-signatures', 'yara', os.path.basename(x)))
                        os.remove(x)
                if set([os.path.basename(x) for x in list_yas_files]).issubset(set(os.listdir(os.path.join(THOR_DIR, 'custom-signatures', 'yara')))):
                    print("[+] Successful add custom signatures\n")
            else:
                print("[-] Failed to encrypt signature files\n")
        else:
            print("[-] Failed to Add custom signatures\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def update_task():
    try:
        print("[*] Updating THOR signatures")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to update THOR signatures\n")
            return

        thor_util_binary = get_thor_util_bin()
        if os.path.isfile(thor_util_binary):
            strCmdUtilVersion = thor_util_binary + " version"
            if get_platform() != 'windows':
                strCmdUtilVersion = './' + strCmdUtilVersion
            strCmdUtilVersionOutput = subprocess.run(shlex.split(strCmdUtilVersion), stdout=subprocess.PIPE)
            print("[+] Checking THOR utility: {0} - v{1}".format(thor_util_binary, strCmdUtilVersionOutput.stdout.decode().splitlines()[-1]))

            strCmdUtilUpdate = thor_util_binary + " update"
            if get_platform() != 'windows':
                strCmdUtilUpdate = './' + strCmdUtilUpdate
            print("[+] Run THOR Update: wait a moment..!")
            strCmdUtilUpdateOutput = subprocess.run(shlex.split(strCmdUtilUpdate), stdout=subprocess.PIPE)
            if 'no valid license' in strCmdUtilUpdateOutput.stdout.decode().lower():
                print("[-] Error: No valid license found\n")
            elif 'up-to-date' in strCmdUtilUpdateOutput.stdout.decode().lower() or 'successfully' in strCmdUtilUpdateOutput.stdout.decode().lower():
                print("[+] Already signatures up-to-date\n")
            else:
                print("[-] Error: Update failed!\n")
        else:
            print("[-] Error: Update failed!\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def upgrade_task():
    try:
        print("[*] Upgrading THOR and signatures")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to upgrade THOR and signatures\n")
            return

        thor_util_binary = get_thor_util_bin()
        thor_scanner_binary = get_thor_scanner_bin()
        if os.path.isfile(thor_util_binary) and os.path.isfile(thor_scanner_binary):
            os_platform = get_platform()
            strCmdUtilVersion = thor_util_binary + " version"
            if os_platform != 'windows':
                strCmdUtilVersion = './' + strCmdUtilVersion
            strCmdUtilVersionOutput = subprocess.run(shlex.split(strCmdUtilVersion), stdout=subprocess.PIPE)
            print("[+] Checking THOR utility: {0} - v{1}".format(thor_util_binary, strCmdUtilVersionOutput.stdout.decode().splitlines()[-1]))

            strCmdThorVersion = thor_scanner_binary + " --version"
            if os_platform != 'windows':
                strCmdThorVersion = './' + strCmdThorVersion
            strCmdThorVersionOutput = subprocess.run(shlex.split(strCmdThorVersion), stdout=subprocess.PIPE)
            strThorVersion = strCmdThorVersionOutput.stdout.decode().splitlines()[0] + " " + strCmdThorVersionOutput.stdout.decode().splitlines()[1]
            print("[+] Checking THOR scanner: {0}".format(strThorVersion))

            strCmdThorUpgrade = thor_util_binary + " upgrade"
            if os_platform != 'windows':
                strCmdThorUpgrade = './' + strCmdThorUpgrade
            print("[+] Run THOR upgrade: wait a moment..!")
            strCmdThorUpgradeOutput = subprocess.run(shlex.split(strCmdThorUpgrade), stdout=subprocess.PIPE)
            if 'no valid license' in strCmdThorUpgradeOutput.stdout.decode().lower():
                print("[-] Error: No valid license found\n")
            elif 'up-to-date' in strCmdThorUpgradeOutput.stdout.decode().lower() or 'successfully' in strCmdThorUpgradeOutput.stdout.decode().lower():
                print("[+] Already signatures up-to-date")
                strCmdThorVersionOutput = subprocess.run(shlex.split(strCmdThorVersion), stdout=subprocess.PIPE)
                strThorVersion = strCmdThorVersionOutput.stdout.decode().splitlines()[0] + " " + strCmdThorVersionOutput.stdout.decode().splitlines()[1]
                print("[+] Current THOR scanner version: {0}\n".format(strThorVersion))
            else:
                print("[-] Error: Upgrade failed!\n")
        else:
            print("[-] Error: Upgrade failed!\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def remove_task(arch):
    try:
        print("[*] Removing THOR optional binaries and dirs")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to remove THOR optional binaries and dirs\n")
            return

        if arch == 'x86':
            all_files_delete_x86 = {*GENERAL_DELETED, *FILES_DELETED_WINDOWS_X86, *FILES_DELETED_LINUX_X86}
            for x in all_files_delete_x86:
                if os.path.isfile(x):
                    os.remove(x)
            for x in DIRS_DELETED:
                shutil.rmtree(x, ignore_errors=True)
            print("[+] Remove x86 binaries and dirs is done.\n")
        elif arch == 'x64':
            all_files_delete_x64 = {*GENERAL_DELETED, *FILES_DELETED_WINDOWS_X64, *FILES_DELETED_LINUX_X64}
            for x in all_files_delete_x64:
                if os.path.isfile(x):
                    os.remove(x)
            for x in DIRS_DELETED:
                shutil.rmtree(x, ignore_errors=True)
            print("[+] Remove x64 binaries and dirs is done.\n")
        else:
            print("[-] The \'{0}\' arch does not support. Please try: --arch=[x86|x64]\n".format(arch))
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def rename_task(prefix):
    try:
        print("[*] Renaming THOR binaries")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to rename THOR binaries\n")
            return
        
        os_platform = get_platform()
        thor_files = list()
        thor_files_sig = list()
        if os_platform == 'windows':
            thor_files = get_windows_thor_scanner_bin()
        elif os_platform == 'linux':
            thor_files = get_linux_thor_scanner_bin()
        elif os_platform == 'macosx':
            thor_files = get_macosx_thor_scanner_bin()
        print("[+] Rename with prefix=\'{0}\'".format(prefix))
        
        for x in thor_files:
            sig_file = x + '.sig'
            thor_files_sig.append(sig_file)
        thor_files = thor_files + thor_files_sig

        for x in thor_files:
            prefix_name = x.replace('thor', prefix)
            os.rename(x, prefix_name)
        
        print("[+] Rename done: {0}\n".format(get_files_in_dir(THOR_DIR)))
        time.sleep(0.5)
        
    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def keygen_task(keyname, length):
    try:
        print("[*] Generating public/private key pair.")
        os.chdir(BASE_DIR)
        generate_rsa_keys(keyname, length)
        rsa_key_files = os.listdir('rsa_keys')
        if '.gitignore' in rsa_key_files:
            rsa_key_files.remove('.gitignore')
        print("[+] Successful! Total keys available {}\n".format(rsa_key_files))
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())


def clean_task():
    try:
        print("[*] Cleaning all temporary working files")
        os.chdir(BASE_DIR)
        if os.path.isdir(THOR_DIR):
            shutil.rmtree(THOR_DIR, ignore_errors=True)
            time.sleep(0.5)
            if not os.path.exists(THOR_DIR):
                print("[+] Clean done.\n")
        else:
            print("[-] Clean failed.\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())


def build_task():
    try:
        print("[*] Build {} Package".format(PRODUCT_NAME))
        if os.path.exists(THOR_DIR):
            os.chdir(BASE_DIR)
        else:
            print("[-] Failed to Build . Make sure {} Bundle created.\n".format(PRODUCT_NAME))
            return

        os_platform = get_platform()
        executable_name = 'thor-apt-scanner'
        launcher_name = 'thor-apt-scanner.py'
        tiny_aes_key = secure_string_random(16)
        release_path = os.path.join('releases', os_platform)

        if os_platform == 'windows':
            upx_packer = os.path.join('packer', 'upx_win64')
            PyInstaller.__main__.run(['--clean', '--uac-admin', '--icon', 'NONE', '--onefile', '--name', executable_name, '--add-data', 'windows;windows',
                                     '--distpath', release_path, '--upx-dir', upx_packer, '--key', tiny_aes_key, launcher_name])
        elif os_platform == 'linux':
            upx_packer = os.path.join('packer', 'upx_lin64')
            PyInstaller.__main__.run(['--clean', '--icon', 'NONE', '--onefile', '--name', executable_name, '--add-data', 'linux:linux',
                                     '--distpath', release_path, '--upx-dir', upx_packer, '--key', tiny_aes_key, launcher_name])
        elif os_platform == 'macosx':
            PyInstaller.__main__.run(['--clean', '--icon', 'NONE', '--onefile', '--name', executable_name, '--add-data', 'macosx:macosx',
                                     '--distpath', release_path, '--key', tiny_aes_key, launcher_name])
        else:
            print("[-] Platform does not support!\n")
        time.sleep(0.5)
        
    except Exception as e:
        logging.error(traceback.format_exc())


def version_task():
    print("{} v{}\n".format(UTILITY_NAME, UTILITY_VERSION))


@click.group()
def cli():
    """A CLI Utility for THOR APT Scanner by HaiLH"""
    pass


@cli.command(name='extract', help='Extract THOR packs')
def extract():
    extract_task()


@cli.command(name='license', help='Add THOR license')
def license():
    license_task()


@cli.command(name='rsakey', help='Add encryption key')
def rsakey():
    rsa_key_task()


@cli.command(name='signature', help='Add custom signatures')
def signature():
    signature_task()


@cli.command(name='update', help='Update signatures')
def update():
    update_task()


@cli.command(name='upgrade', help='Upgrade THOR and signatures')
def upgrade():
    upgrade_task()


@cli.command(name='remove', help='Remove THOR optional binaries and dirs')
@click.option('--arch', default='x86', type=str, help='--arch=[x86|x64]')
def remove(arch):
    remove_task(arch)


@cli.command(name='rename', help='Rename THOR binaries')
@click.option('--prefix', default='hailh', type=str, help='--prefix=hailh')
def rename(prefix):
    rename_task(prefix)


@cli.command(name='clean', help='Clean all temporary working files')
def upgrade():
    clean_task()


@cli.command(name='keygen', help='RSA keys generator')
@click.option('-k', '--keyname', type=str, help='Example: --keyname \"key\"', required=True)
@click.option('-l', '--length', type=int, help='Example: --length [1024|2048|4096]', required=True)
def keygen(keyname, length):
    keygen_task(keyname, length)


@cli.command(name='version', help='Show Utility version')
def version():
    version_task()


@cli.command(name='make', help='Create {} bundle'.format(PRODUCT_NAME))
def make():
    print("[*] Creating {} bundle".format(PRODUCT_NAME))
    extract_task()
    license_task()
    rsa_key_task()
    signature_task()
    upgrade_task()
    remove_task('x86')
    rename_task('hailh')


@cli.command(name='build', help='Build {} package'.format(PRODUCT_NAME))
def build():
    build_task()


if __name__ == '__main__':
    cli()
