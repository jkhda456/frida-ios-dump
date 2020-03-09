# frida-ios-dump
Pull a decrypted IPA from a jailbroken device

copy from github.com/AloneMonkey/frida-ios-dump

Modify for me(JKH)

## Usage

 1. Install [frida](http://www.frida.re/) on device
 2. `sudo pip install -r requirements.txt --upgrade`
 3. Run usbmuxd/iproxy SSH forwarding over USB (Default 2222 -> 22). e.g. `iproxy 2222 22`
 4. Run ./dump.py `Display name` or `Bundle identifier`

 or

 1. Install [frida](http://www.frida.re/) on device
 2. `sudo pip install -r requirements.txt --upgrade`
 3. Run ./dump.py -H [device address] `Display name` or `Bundle identifier`

## Support

Python 2.x and 3.x

### issues

If the following error occurs:

* causes device to reboot
* lost connection
* unexpected error while probing dyld of target process

please open the application before dumping.
