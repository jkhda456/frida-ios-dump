#!/usr/bin/env python
# -*- coding: utf-8 -*-

# orginal version
# Author : AloneMonkey
# blog: www.alonemonkey.com

# mod by jkh - https://github.com/jkhda456/frida-ios-dump
# 2023/03/30

from __future__ import print_function
from __future__ import unicode_literals
import importlib
import sys
import codecs
import frida
import threading
import os
import stat
import shutil
import time
import argparse
import tempfile
import subprocess
import re
import paramiko
import zipfile
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback

IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')

script_dir = os.path.dirname(os.path.realpath(__file__))

User = 'root'
Password = 'alpine'
Host = ''
Port = 22

use_delay = 0
use_nowait = False
skip_payload = False

baseScript = """
Module.ensureInitialized('Foundation');

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function putStr(addr, str) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeUtf8String(addr, str);
}

function getByteArr(addr, l) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readByteArray(addr, l);
}

function getU8(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU8(addr);
}

function putU8(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU8(addr, n);
}

function getU16(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU16(addr);
}

function putU16(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU16(addr, n);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU32(addr);
}

function putU32(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU32(addr, n);
}

function getU64(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU64(addr);
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU64(addr, n);
}

function getPt(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readPointer(addr);
}

function putPt(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    if (typeof n == "number") {
        n = ptr(n);
    }
    return Memory.writePointer(addr, n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);
var remove = getExportFunction("f", "remove", "int", ["pointer"]);
var access = getExportFunction("f", "access", "int", ["pointer", "int"]);
var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);

function getDocumentDir() {
    var NSDocumentDirectory = 9;
    var NSUserDomainMask = 1;
    var npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
    return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

var modules = null;
function getAllAppModules() {
    modules = new Array();
    var tmpmods = Process.enumerateModulesSync();
    for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str, n) {
    return Array(n-str.length+1).join("0")+str;
}

function swap32(value) {
    value = pad(value.toString(16),8)
    var result = "";
    for(var i = 0; i < value.length; i=i+2){
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result,16)
}

function hashCode(s) {
  var h = 0, l = s.length, i = 0;
  if ( l > 0 )
    while (i < l)
      h = (h << 5) - h + s.charCodeAt(i++) | 0;
  return h;
};

function dumpModule(name) {
    if (modules == null) {
        modules = getAllAppModules();
    }

    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        console.log("Cannot find module");
        return;
    }
    var modbase = modules[i].base;
    var modsize = modules[i].size;
    var newmodname = modules[i].name;
    var newmodpath = getDocumentDir() + "/" + newmodname + "." + hashCode(modules[i].path) + ".fid";
    var oldmodpath = modules[i].path;


    if(!access(allocStr(newmodpath),0)){
        remove(allocStr(newmodpath));
    }

    var fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
    var foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) {
        console.log("Cannot open file" + newmodpath);
        return;
    }

    var is64bit = false;
    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    }else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    var BUFSIZE = 4096;
    var buffer = malloc(BUFSIZE);

    read(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    magic = getU32(buffer);
    if(magic == FAT_CIGAM || magic == FAT_MAGIC){
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if(cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype){
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        if(fileoffset == 0 || filesize == 0)
            return;

        lseek(fmodule, 0, SEEK_SET);
        lseek(foldmodule, fileoffset, SEEK_SET);
        for(var i = 0; i < parseInt(filesize / BUFSIZE); i++) {
            read(foldmodule, buffer, BUFSIZE);
            write(fmodule, buffer, BUFSIZE);
        }
        if(filesize % BUFSIZE){
            read(foldmodule, buffer, filesize % BUFSIZE);
            write(fmodule, buffer, filesize % BUFSIZE);
        }
    }else{
        var readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        lseek(fmodule, 0, SEEK_SET);
        while(readLen = read(foldmodule, buffer, BUFSIZE)) {
            write(fmodule, buffer, readLen);
        }
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    var segments = [];
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }

    if (offset_cryptid != -1) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek(fmodule, offset_cryptid, SEEK_SET);
        write(fmodule, tpbuf, 4);
        lseek(fmodule, crypt_off, SEEK_SET);
        write(fmodule, modbase.add(crypt_off), crypt_size);
    } else {
        console.log("[frida-ios-dump]: offset_cryptid -1");
    }

    close(fmodule);
    close(foldmodule);
    return newmodpath
}

function loadAllDynamicLibrary(app_path) {
    var defaultManager = ObjC.classes.NSFileManager.defaultManager();
    var errorPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errorPtr, NULL);
    var filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (var i = 0, l = filenames.count(); i < l; i++) {
        var file_name = filenames.objectAtIndex_(i);
        var file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            var bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                console.log("[frida-ios-dump]: " + file_name + " has been loaded. ");
            } else {
                if (bundle.load()) {
                    console.log("[frida-ios-dump]: Load " + file_name + " success. ");
                } else {
                    console.log("[frida-ios-dump]: Load " + file_name + " failed. ");
                }
            }
        } else if (file_name.hasSuffix_(".bundle") ||
                   file_name.hasSuffix_(".momd") ||
                   file_name.hasSuffix_(".strings") ||
                   file_name.hasSuffix_(".appex") ||
                   file_name.hasSuffix_(".app") ||
                   file_name.hasSuffix_(".lproj") ||
                   file_name.hasSuffix_(".storyboardc")) {
            continue;
        } else {
            var isDirPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(isDirPtr,NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            if (Memory.readPointer(isDirPtr) == 1) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    for (var j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            console.log("[frida-ios-dump]: " + file_name + " has been dlopen.");
                            break;
                        }
                    }

                    if (!is_loaded) {
                        if (dlopen(allocStr(file_path.UTF8String()), 9)) {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " success. ");
                        } else {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " failed. ");
                        }
                    }
                }
            }
        }
    }
}

function handleMessage(message) {
    modules = getAllAppModules();
    var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
    loadAllDynamicLibrary(app_path);
    // start dump
    modules = getAllAppModules();
    for (var i = 0; i  < modules.length; i++) {
        console.log("start dump " + modules[i].path);
        var result = dumpModule(modules[i].path);
        send({ dump: result, path: modules[i].path});
    }

    """
baseScriptTail = """

    send({done: "ok"});
    recv(handleMessage);
}

recv(handleMessage);
"""

TEMP_DIR = tempfile.gettempdir()
# print(TEMP_DIR) # for debug jkh
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
file_dict = {}

finished = threading.Event()

def get_usb_iphone():
    # https://github.com/frida/frida-python/issues/189
    importlib.reload(frida)
    devices = frida.enumerate_devices()

    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    waitCount = 0

    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait(timeout=1)
            waitCount += 1
            if waitCount >= 5:
                print('device not found!')
                sys.exit(exit_code)
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device

def makeZipping(outputFile, target_dir, base_dir):
    zipobj = zipfile.ZipFile(outputFile, 'w', zipfile.ZIP_DEFLATED)
    if base_dir == '':
        rootlen = len(target_dir) + 1
    else:
        rootlen = len(base_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            zipobj.write(fn, fn[rootlen:])

def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'

    print('Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                if os.name == 'nt':
                    os.chmod( from_dir, stat.S_IWRITE )
                    os.chmod( to_dir, stat.S_IWRITE )

                work_dir = os.path.dirname(to_dir)
                if not os.path.isdir(work_dir):
                    os.makedirs(work_dir)
                shutil.move(from_dir, to_dir)

        target_dir = os.path.join('.', PAYLOAD_DIR)

        # bad.
        #zip_args = ('zip', '-qr', os.path.join(os.getcwd(), ipa_filename), target_dir)
        #subprocess.check_call(zip_args, cwd=TEMP_DIR)

        #os.chmod( target_dir, stat.S_IWRITE )
        makeZipping(os.path.join(os.getcwd(), ipa_filename), path, os.path.dirname(path))

        shutil.rmtree(PAYLOAD_PATH, onerror=on_rm_error)
    except Exception as e:
        print(e)
        finished.set()

def on_message(message, data):
    t = tqdm(unit='B',unit_scale=True,unit_divisor=1024,miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        baseName = os.path.basename(filename)
        '''
        if IS_PY2:
            t.desc = baseName.decode("utf-8")
        else:
            t.desc = baseName
        '''
        t.total = size
        t.update(int(sent - last_sent[0]))
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        print("payload : " + str(payload))
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']

            scp_from = dump_path
            scp_to = PAYLOAD_PATH + '/'
            #print('debug src: ' + origin_path)
            #print('debug to : ' + scp_to)

            with SCPClient(ssh.get_transport(), progress = progress, socket_timeout = 60) as scp:
                scp.get(scp_from, scp_to)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            chmod_args = ('chmod', '655', chmod_dir)

            if os.name != 'nt':
                try:
                    subprocess.check_call(chmod_args)
                except subprocess.CalledProcessError as err:
                    print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']

            global skip_payload
            if not skip_payload:
                scp_from = app_path
                scp_to = PAYLOAD_PATH + '/'
                print(scp_to)
                with SCPClient(ssh.get_transport(), progress = progress, socket_timeout = 60) as scp:
                    scp.get(scp_from, scp_to, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            chmod_args = ('chmod', '755', chmod_dir)

            if os.name != 'nt':
                try:
                    subprocess.check_call(chmod_args)
                except subprocess.CalledProcessError as err:
                    print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            print("DONE!")
            finished.set()
    t.close()

def compare_applications(a, b):
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        if a.name > b.name:
            return 1
        elif a.name < b.name:
            return -1
        else:
            return 0
    elif a_is_running:
        return -1
    else:
        return 1


def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""

    class K:
        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

    return K


def get_applications(device):
    try:
        applications = device.enumerate_applications()
    except Exception as e:
        sys.exit('Failed to enumerate applications: %s' % e)

    return applications


def list_applications(device):
    applications = get_applications(device)

    if len(applications) > 0:
        pid_column_width = max(map(lambda app: len('{}'.format(app.pid)), applications))
        name_column_width = max(map(lambda app: len(app.name), applications))
        identifier_column_width = max(map(lambda app: len(app.identifier), applications))
    else:
        pid_column_width = 0
        name_column_width = 0
        identifier_column_width = 0

    header_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print('%s  %s  %s' % (pid_column_width * '-', name_column_width * '-', identifier_column_width * '-'))
    line_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    for application in sorted(applications, key=cmp_to_key(compare_applications)):
        if application.pid == 0:
            print(line_format % ('-', application.name, application.identifier))
        else:
            print(line_format % (application.pid, application.name, application.identifier))


def load_js_file(session, filename):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.load()
    script.on('message', on_message)

    return script


def create_dir(path):
    path = path.strip()
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)


def open_target_app(device, name_or_bundleid):
    print('Start the target app {}'.format(name_or_bundleid))

    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for application in get_applications(device):
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid)
            if use_nowait: # if drop flag works!
                device.resume(pid)
            print("spawn pid : " + str(pid))
        else:
            session = device.attach(pid)
            print("attach pid : " + str(pid))
    except Exception as e:
        print(e)

    return session, display_name, bundle_identifier


def start_dump(session, ipa_name):
    print('Dumping {} to {}'.format(display_name, TEMP_DIR))

    #script = load_js_file(session, DUMP_JS)
    script = session.create_script(baseScript)
    script.on('message', on_message)
    script.load()
    script.post('dump')
    finished.wait()

    generate_ipa(PAYLOAD_PATH, ipa_name)

    if session:
        session.detach()

def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump-mod (by AloneMonkey v2.0 / mod by jkh v1.0)')
    parser.add_argument('-l', '--list', dest='list_applications', action='store_true', help='List the installed apps')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-H', '--host', dest='ssh_host', help='Specify SSH hostname')
    parser.add_argument('-p', '--port', dest='ssh_port', help='Specify SSH port')
    parser.add_argument('-u', '--user', dest='ssh_user', help='Specify SSH username')
    parser.add_argument('-P', '--password', dest='ssh_password', help='Specify SSH password')
    # add by jkh
    parser.add_argument('-S', '--skip-payload', dest='skip_payload', action='store_true', help='Skip payload download')
    parser.add_argument('-E', '--delay', dest='delay_attach', help='Put a delay for attach')
    parser.add_argument('-W', '--nowait', dest='nowait', action='store_true', help='Spawned process will be resumed')

    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')

    args = parser.parse_args()

    exit_code = 0
    ssh = None

    if not len(sys.argv[1:]):
        parser.print_help()
        sys.exit(exit_code)

    device = get_usb_iphone()

    if args.list_applications:
        list_applications(device)
    else:
        name_or_bundleid = args.target
        output_ipa = args.output_ipa
        # update ssh args
        if args.ssh_host:
            Host = args.ssh_host
        if args.ssh_port:
            Port = int(args.ssh_port)
        if args.ssh_user:
            User = args.ssh_user
        if args.ssh_password:
            Password = args.ssh_password
        if args.skip_payload:
            skip_payload = True
        if args.delay_attach:
            use_delay = int(args.delay_attach)
        if args.nowait:
            use_nowait = True

        baseScript = baseScript + "send({app: app_path.toString()});" + baseScriptTail

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(Host, port=Port, username=User, password=Password, timeout=2)

            if os.path.isdir(PAYLOAD_PATH):
                shutil.rmtree(PAYLOAD_PATH, onerror=on_rm_error)

            create_dir(PAYLOAD_PATH)
            (session, display_name, bundle_identifier) = open_target_app(device, name_or_bundleid)
            if output_ipa is None:
                output_ipa = display_name
            output_ipa = re.sub('\.ipa$', '', output_ipa)
            if session:
                if use_delay > 0:
                    time.sleep(use_delay)
                start_dump(session, output_ipa)
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(e)
            print('Try specifying -H/--hostname and/or -p/--port')
            exit_code = 1
        except paramiko.AuthenticationException as e:
            print(e)
            print('Try specifying -u/--username and/or -P/--password')
            exit_code = 1
        except Exception as e:
            print('*** Caught exception: %s: %s' % (e.__class__, e))
            traceback.print_exc()
            exit_code = 1

    if ssh:
        ssh.close()

    if os.path.exists(PAYLOAD_PATH):
        shutil.rmtree(PAYLOAD_PATH, onerror=on_rm_error)

    sys.exit(exit_code)
