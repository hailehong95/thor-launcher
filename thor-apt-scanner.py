#!/usr/bin/env python3

import os
import sys
import stat
import time
import shlex
import click
import zipfile
import logging
import binascii
import datetime
import platform
import traceback
import subprocess


def get_platform():
    if platform.system().lower() == 'darwin':
        return 'macosx'
    return platform.system().lower()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
THOR_DIR = os.path.join(BASE_DIR, get_platform())
EXEC_DIR = os.getcwd()
PRODUCT_NAME = 'THOR APT Scanner'
PRODUCT_VERSION = '1.0'


def get_files_in_dir(dir_name):
    try:
        if os.path.exists(dir_name):
            files_and_dirs = os.listdir(dir_name)
            files = [x for x in files_and_dirs if os.path.isfile(os.path.join(dir_name, x))]
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


def get_thor_report():
    try:
        hostname = platform.node().lower()
        list_files_thor_dir = get_files_in_dir(THOR_DIR)
        thor_files_report = [x for x in list_files_thor_dir if hostname in x.lower()]
        return thor_files_report

    except Exception as e:
        logging.error(traceback.format_exc())


def zipping_thor_report(zip_name):
    try:
        thor_files_report = get_thor_report()
        with zipfile.ZipFile(os.path.join(EXEC_DIR, zip_name), 'w') as zipObj:
            for x in thor_files_report:
                zipObj.write(x)

    except Exception as e:
        logging.error(traceback.format_exc())


def file_task(path):
    try:
        print("[*] SCAN Files: Scan a specific file path")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to SCAN Files\n")
            return

        if os.path.exists(path):
            thor_scanner_binary = get_thor_scanner_bin()
            if os.path.isfile(thor_scanner_binary):
                # I hard-code the rsa public key file name, replace it with your key! =))
                strCmdThorScanFiles = thor_scanner_binary + " --silent --jsonfile --encrypt --pubkey hailh-rsa-public.pem --fsonly --path"
                if get_platform() != 'windows':
                    strCmdThorScanFiles = './' + strCmdThorScanFiles
                strCmdThorScanFiles = shlex.split(strCmdThorScanFiles, posix=False)
                strCmdThorScanFiles.append(path)
                strCmdThorScanFilesOutput = subprocess.call(strCmdThorScanFiles)
                total_thor_report = get_thor_report()
                print("[+] SCAN files done. Total {} report files: {}".format(len(total_thor_report), total_thor_report))
                zip_name = platform.node().lower() + '-' + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.zip'
                zipping_thor_report(zip_name)
                print("[+] Zipping report successful: {}\n".format(zip_name))
            else:
                print("[-] SCAN Files: Failed!\n")
        else:
            print("[-] Invalid Path.\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def proc_task():
    try:
        print("[*] SCAN Process: Process images and connections")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to SCAN Process\n")
            return
        thor_scanner_binary = get_thor_scanner_bin()
        if os.path.isfile(thor_scanner_binary):
            # I hard-code the rsa public key file name, replace it with your key! =))
            strCmdThorScanProc = thor_scanner_binary + " --silent --jsonfile --noautoruns --nofilesystem --encrypt --pubkey hailh-rsa-public.pem"
            if get_platform() != 'windows':
                strCmdThorScanProc = './' + strCmdThorScanProc
            strCmdThorScanProcOutput = subprocess.call(shlex.split(strCmdThorScanProc, posix=False))
            total_thor_report = get_thor_report()
            print("[+] SCAN Process done. Total {} report files: {}".format(len(total_thor_report), total_thor_report))
            zip_name = platform.node().lower() + '-' + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.zip'
            zipping_thor_report(zip_name)
            print("[+] Zipping report successful: {}\n".format(zip_name))
        else:
            print("[-] SCAN Process: Failed!\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def auto_task():
    try:
        print("[*] SCAN Autoruns: Auto-starting programs")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to SCAN Autoruns\n")
            return
        
        thor_scanner_binary = get_thor_scanner_bin()
        if os.path.isfile(thor_scanner_binary):
            # I hard-code the rsa public key file name, replace it with your key! =))
            strCmdThorScanAutoruns = thor_scanner_binary + " --silent --jsonfile --nofilesystem --noprocs --encrypt --pubkey hailh-rsa-public.pem"
            if get_platform() != 'windows':
                strCmdThorScanAutoruns = './' + strCmdThorScanAutoruns
            strCmdThorScanAutorunsOutput = subprocess.call(shlex.split(strCmdThorScanAutoruns, posix=False))
            total_thor_report = get_thor_report()
            print("[+] SCAN Autoruns done. Total {} report files: {}".format(len(total_thor_report), total_thor_report))
            zip_name = platform.node().lower() + '-' + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.zip'
            zipping_thor_report(zip_name)
            print("[+] Zipping report successful: {}\n".format(zip_name))
        else:
            print("[-] SCAN Autoruns: Failed!\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def default_task():
    try:
        print("[*] SCAN ALL available modules")
        if os.path.exists(THOR_DIR):
            os.chdir(THOR_DIR)
        else:
            print("[-] Failed to SCAN ALL available modules\n")
            return
        
        thor_scanner_binary = get_thor_scanner_bin()
        if os.path.isfile(thor_scanner_binary):
            # I hard-code the rsa public key file name, replace it with your key! =))
            strCmdThorScanAllModules = thor_scanner_binary + " --silent --jsonfile --encrypt --pubkey hailh-rsa-public.pem"
            if get_platform() != 'windows':
                strCmdThorScanAllModules = './' + strCmdThorScanAllModules
            strCmdThorScanAllModulesOutput = subprocess.call(shlex.split(strCmdThorScanAllModules, posix=False))
            total_thor_report = get_thor_report()
            print("[+] SCAN ALL modules done. Total {} report files: {}".format(len(total_thor_report), total_thor_report))
            zip_name = platform.node().lower() + '-' + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.zip'
            zipping_thor_report(zip_name)
            print("[+] Zipping report successful: {}\n".format(zip_name))
        else:
            print("[-] SCAN ALL modules: Failed!\n")
        time.sleep(0.5)

    except Exception as e:
        logging.error(traceback.format_exc())
    finally:
        os.chdir(BASE_DIR)


def version_task():
    print("{} v{}\n".format(PRODUCT_NAME, PRODUCT_VERSION))
    

@click.group()
def cli():
    """A CLI Launcher for the THOR APT Scanner by HaiLH"""
    pass


@cli.command(name='file', help='SCAN Files: Scan a specific file path')
@click.option('-p', '--path', type=str, help='Example: --path \"C:\TMP\\"', required=True)
def file(path):
    file_task(path)


@cli.command(name='proc', help='SCAN Process: Process images and connections')
def proc():
    proc_task()


@cli.command(name='auto', help='SCAN Autoruns: Auto-starting programs')
def auto():
    auto_task()


@cli.command(name='all', help='SCAN ALL available modules')
def all():
    default_task()


@cli.command(name='version', help='SHOW {} version'.format(PRODUCT_NAME))
def version():
    version_task()


if __name__ == '__main__':
    cli()
