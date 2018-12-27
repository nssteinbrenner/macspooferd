#!/usr/bin/env python

import signal
import resource
import json
import argparse
import subprocess
import binascii
import time
import os
import re
import random
import sys


parser = argparse.ArgumentParser(prog="Mac Spoofer",
                                 description="Mac Spoofing Daemon",
                                 )

parser.add_argument("-i",
                    "--interface",
                    nargs="*",
                    default=None,
                    required=False,
                    help=("Specify interfaces on which to spoof the mac. "
                          "Default is all interfaces."
                          ),
                    )

parser.add_argument("-v",
                    "--vendor",
                    default=None,
                    required=False,
                    help=("Specify vendor OUI for the mac. "
                          "Default is random OUI."
                          ),
                    )

parser.add_argument("-f",
                    "--force",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("Force a mac address change from the daemon "
                          "if the daemon is running.\nWill not work without "
                          "the daemon running in the background."
                          ),
                    )

parser.add_argument("-m",
                    "--mac",
                    default=None,
                    required=False,
                    help=("Set the mac to XX:XX:XX:XX:XX:XX and exit. "
                          "Can only be run with '-i <ifname>'"
                          ),
                    )

parser.add_argument("-s",
                    "--show",
                    default=None,
                    action="store_true",
                    required=False,
                    help=("Print the MAC address and exit."
                          ),
                    )

parser.add_argument("-e",
                    "--ending",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("Use current OUI"
                          ),
                    )

parser.add_argument("-a",
                    "--another",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("Set random OUI from same vendor as current."
                          ),
                    )

parser.add_argument("-r",
                    "--random",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("Set fully random MAC."
                          ),
                    )

parser.add_argument("-l",
                    "--list",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("List all known vendors and exit. "
                          "NOTE: File is large. Redirect output or grep it."
                          ),
                    )

parser.add_argument("-d",
                    "--daemonize",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("Run as a daemon."
                          ),
                    )

parser.add_argument("-o",
                    "--original",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("Reset MAC address to original and exit."
                          ),
                    )

args = parser.parse_args()


def getInterfaces():
    interfaces = {}

    for interface in os.listdir("/sys/class/net"):
        try:
            with open(f"/sys/class/net/{interface}/"
                      "address", "r"
                      ) as f:
                mac = f.read(18).strip()

        except OSError as e:
            mac = None
            print(f"Error accessing /sys/class/net/{interface}/address. "
                  f"File may not exist or be readable.\n{e}"
                  )
        try:

            with open(f"/sys/class/net/{interface}/"
                      "addr_assign_type", "r"
                      ) as f:
                if f.read(1).strip() == "0":
                    isOriginal = True
                else:
                    isOriginal = False

        except OSError as e:
            isOriginal = None
            print(f"Error accessing /sys/class/net/{interface}/"
                  f"addr_assign_type. File may not exist or be readable.\n{e}"
                  )
        try:

            with open(f"/sys/class/net/{interface}/"
                      "carrier", "r"
                      ) as f:
                if f.read(1).strip() == "1":
                    up = True
                else:
                    up = False

        except OSError as e:
            up = None
            print(f"Error accessing /sys/class/net/{interface}/carrier. "
                  f"File may not exist or be readable.\n{e}"
                  )

        if isOriginal is True:
            originMac = mac
        elif os.path.isfile("/etc/macspoofer/interfaces"):
            try:
                with open("/etc/macspoofer/interfaces", "r") as f:
                    storedif = json.load(f)
                    originMac = storedif[interface]["original"]
            except KeyError as e:
                originMac = None
        else:
            originMac = None

        interfaces[interface] = {"up": up,
                                 "mac": mac,
                                 "mac-is-original": isOriginal,
                                 "original": originMac,
                                 }
    try:
        with open("/etc/macspoofer/interfaces", "r") as f:
            storedif = json.load(f)
    except (FileNotFoundError, NotADirectoryError) as e:
        print("/etc/macspoofer/interfaces not found. Creating file.")
        if os.path.exists("/etc/macspoofer"):
            os.remove("/etc/macspoofer")
            os.mkdir("/etc/macspoofer")
        elif not os.path.isdir("/etc/macspoofer"):
            os.mkdir("/etc/macspoofer")
        with open("/etc/macspoofer/interfaces", "w+") as f:
            f.write(json.dumps(interfaces,
                               sort_keys=True,
                               indent=4,
                               separators=(",\n", ": "),
                               )
                    )
            f.seek(0)
            storedif = json.load(f)
    finally:
        if storedif != json.dumps(interfaces):
            with open("/etc/macspoofer/interfaces", "w") as f:
                f.write(json.dumps(interfaces,
                                   sort_keys=True,
                                   indent=4,
                                   separators=(",\n", ": "),
                                   )
                        )

    return interfaces


def checkModified(interface, modTime):
    if os.path.getmtime(f"/sys/class/net/{interface}/carrier") > modTime:
        return True
    else:
        return False


def getAllOui():
    with open("oui.txt", "r") as f:
        ouiList = [line.split(" ") for line in f.readlines()]

    return ouiList


def genMac(ouiList, vendor):
    if vendor:
        targets = [oui for oui in ouiList
                   if f"{vendor.strip()} " in " ".join(oui)
                   ]

        if len(targets) > 1:
            oui = targets[random.randint(0, len(targets)-1)][0]
        else:
            oui = targets[0]
    else:
        oui = ouiList[random.randint(0, len(ouiList)-1)][0]

    oui = ":".join([oui[i:i+2] for i in range(0, len(oui)+1, 2)])

    token_bytes = os.urandom(3)
    mac = binascii.hexlify(token_bytes).decode("ascii")
    mac = (oui + ":".join([mac[i:i+2] for i in range(0, len(mac), 2)]))
    return mac


def genEndingMac(interface, interfaces):
    oui = interfaces[interface]["mac"][0:9]
    token_bytes = os.urandom(3)
    mac = binascii.hexlify(token_bytes).decode("ascii")
    mac = (oui + ":".join([mac[i:i+2] for i in range(0, len(mac), 2)]))
    return mac


def checkVendor(interface, interfaces, ouiList):
    vendor = None
    currentOui = interfaces[interface]["mac"].replace(":", "")[0:6]
    for oui in ouiList:
        if currentOui in oui:
            vendor = " ".join(oui[1:]).strip()
            break
    return vendor


def changeMac(interface, interfaces, newMac):
    try:
        if not checkValidMac(newMac):
            raise ValueError(f"MAC address {args.mac} is "
                             "in an unaccepted format. Accepted "
                             "formats are:\n\tXX:XX:XX:XX:XX:XX "
                             "\n\tXX-XX-XX-XX-XX-XX"
                             )
    except AttributeError as e:
        newMac = interfaces[interface]["mac"]

    oldMac = interfaces[interface]["mac"]

    subprocess.call(["ip", "link", "set", "dev", interface, "down"])
    subprocess.call(["ip", "link", "set", "dev", interface, "address", newMac])
    subprocess.call(["ip", "link", "set", "dev", interface, "up"])

    print(f"{interface} - Old MAC Address: {oldMac}\n"
          f"{' '*len(interface)} - New MAC address: {newMac}"
          )

    return newMac


def checkValidMac(mac):
    if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                mac.lower(),
                ):
        return True
    else:
        return False


def forceChange(interfaces):
    def updateModTime(interfaces):
        for interface in interfaces:
            ifCarrier = f"/sys/class/net/{interface}/carrier"
            open(ifCarrier, "a").close()
            os.utime(ifCarrier, None)

    procs = [proc.decode().strip()
             for proc in (subprocess.Popen(["pgrep", "python"],
                                           stdout=subprocess.PIPE
                                           ).stdout.readlines()
                          ) if proc != str(os.getpid())

             ]

    if len(procs) == 0:
        raise Exception("Cannot find any running python instances.")

    foundProc = False
    currentInterfaces = []

    for pid in procs:
        if foundProc is True:
            break
        else:
            procCmd = f"/proc/{pid}/cmdline"
            with open(procCmd, "r") as f:
                cmdArgs = f.read()
            if __file__ in cmdArgs:
                foundProc = True
                splitArgs = cmdArgs.split("\x00")
                start = None
                for arg in splitArgs:
                    if "-i" in arg:
                        start = (splitArgs.index("-i") + 1)
                        break
                if start:
                    for i in splitArgs[start:]:
                        if "-" in i:
                            break
                        else:
                            currentInterfaces.append(i)

    if foundProc is not True:
        raise Exception("Cannot find daemon running in processes."
                        " The -f/--force flag can only be run"
                        " when there is an active daemon running."
                        )

    if len(currentInterfaces):
        updateModTime(currentInterfaces)
    else:
        updateModTime(interfaces)


def watcher(interface,
            interfaces,
            ouiList,
            ending=False,
            another=False,
            random=False,
            vendor=False,
            ):
    modTime = 0
    if not interface:
        interface = list(interfaces.keys())[:]
    for ifname in interface:
        while True:
            if checkModified(ifname, modTime):
                if ifname not in interfaces.keys():
                    raise ValueError(f"Interface {interface} could "
                                     "not be found. Check 'ip a s' "
                                     "or 'ip link' output for available "
                                     "interfaces."
                                     )
                if ending:
                    changeMac(ifname,
                              interfaces,
                              genEndingMac(ifname,
                                           interfaces,
                                           )
                              )
                if another:
                    changeMac(ifname,
                              interfaces,
                              genMac(ouiList,
                                     checkVendor(ifname,
                                                 interfaces,
                                                 ouiList,
                                                 )
                                     )
                              )
                if random or vendor:
                    changeMac(ifname,
                              interfaces,
                              genMac(ouiList,
                                     vendor,
                                     )
                              )
                modTime = time.time()
            time.sleep(0.2)


def createDaemon():
    umask = 0
    workdir = "/"
    maxfdLimit = 1024

    if hasattr(os, "devnull"):
        redirectTo = os.devnull
    else:
        redirectTo = "/dev/null"

    try:
        pid = os.fork()
    except OSError as e:
        raise Exception(f"{e.strerror}, {e.errno}")

    if pid == 0:
        os.setsid()

        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        try:
            pid = os.fork()
        except OSError as e:
            raise Exception(f"{e.strerror}, {e.errno}")

        if pid == 0:
            os.chdir(workdir)
            os.umask(umask)
        else:
            os._exit(0)
    else:
        os._exit(0)

    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if maxfd == resource.RLIM_INFINITY:
        maxfd = maxfdLimit

    for fd in range(0, maxfd):
        try:
            os.close(fd)
        except OSError:
            pass

    os.open(redirectTo, os.O_RDWR)

    os.dup2(0, 1)
    os.dup2(0, 2)

    return(0)


def main():
    interfaces = getInterfaces()
    ouiList = getAllOui()

    if args.random and any([args.vendor,
                            args.mac,
                            args.ending,
                            args.another,
                            args.original,
                            args.force,
                            args.show,
                            args.list,
                            ]
                           ):
        parser.error("-r/--random can only be used with the following flags:"
                     "\n\t-i/--interface\n\t-d/--daemonize"
                     )

    if args.mac and any([args.vendor,
                         args.ending,
                         args.another,
                         args.random,
                         args.original,
                         args.force,
                         args.show,
                         args.list,
                         args.daemonize
                         ]
                        ):
        parser.error("-m/--mac can only be used with the following flags:"
                     "\n\t-i/--interface"
                     )

    if args.ending and any([args.vendor,
                            args.mac,
                            args.another,
                            args.random,
                            args.original,
                            args.force,
                            args.show,
                            args.list,
                            ]
                           ):
        parser.error("-e/--ending can only be used with the following flags:"
                     "\n\t-i/--interface\n\t-d/--daemonize"
                     )

    if args.another and any([args.vendor,
                             args.mac,
                             args.ending,
                             args.random,
                             args.original,
                             args.force,
                             args.show,
                             args.list,
                             ]
                            ):
        parser.error("-a/--another can only be used with the following flags:"
                     "\n\t-i/--interface\n\t-d/--daemonize"
                     )

    if args.original and any([args.vendor,
                              args.mac,
                              args.ending,
                              args.random,
                              args.another,
                              args.force,
                              args.show,
                              args.list,
                              args.daemonize
                              ]
                             ):
        parser.error("-o/--original can only be used with the following flags:"
                     "\n\t-i/--interface"
                     )

    if args.force:
        forceChange(list(interfaces.keys())[:])
        sys.exit(0)

    if args.list:
        for oui in ouiList:
            print(" ".join(oui).strip())
        sys.exit(0)

    if args.daemonize:
        retCode = createDaemon()
        watcher(args.interface,
                interfaces,
                ouiList,
                ending=args.ending,
                another=args.another,
                random=args.random,
                vendor=args.vendor,
                )
        sys.exit(retCode)

    if args.interface and not args.daemonize:
        for interface in args.interface:
            if interface not in interfaces.keys():
                raise ValueError(f"Interface {interface} could not be found."
                                 "Check 'ip a s' or 'ip link' output for "
                                 "available interfaces."
                                 )

            if args.mac:
                if checkValidMac(args.mac.strip()):
                    if '-' in args.mac.strip():
                        formattedMac = args.mac.strip().replace('-', ':')
                        changeMac(interface,
                                  interfaces,
                                  formattedMac,
                                  )
                    else:
                        changeMac(interface,
                                  interfaces,
                                  args.mac.strip(),
                                  )
                else:
                    raise ValueError(f"MAC address {args.mac} is "
                                     "in an unaccepted format. Accepted "
                                     "formats are:\n\tXX:XX:XX:XX:XX:XX "
                                     "\n\tXX-XX-XX-XX-XX-XX"
                                     )
            if args.another:
                changeMac(interface,
                          interfaces,
                          genMac(ouiList,
                                 checkVendor(interface,
                                             interfaces,
                                             ouiList,
                                             )
                                 )
                          )
            if args.ending:
                changeMac(interface,
                          interfaces,
                          genEndingMac(interface,
                                       interfaces,
                                       )
                          )
            if args.show:
                print(f'"{interface}" ' +
                      json.dumps(interfaces[interface],
                                 sort_keys=True,
                                 indent=4,
                                 separators=(",\n", ": "),
                                 ) + "\n"
                      )
            if args.original:
                changeMac(interface,
                          interfaces,
                          interfaces[interface]["original"],
                          )
        sys.exit(0)

    elif not args.interface and not args.daemonize:
        if args.show:
            print(json.dumps(interfaces,
                             sort_keys=True,
                             indent=4,
                             separators=(",\n", ": "),
                             )
                  )
            sys.exit(0)
        for interface in interfaces.keys():
            if args.mac:
                parser.error("Can only run -m/--mac on specified "
                             "interfaces(s) Please specify "
                             "interfaces(s) with -i <ifname>"
                             )
            if args.another:
                changeMac(interface,
                          interfaces,
                          genMac(ouiList,
                                 checkVendor(interface,
                                             interfaces,
                                             ouiList,
                                             )
                                 )
                          )
            if args.ending:
                changeMac(interface,
                          interfaces,
                          genEndingMac(interface,
                                       interfaces,
                                       )
                          )
            if args.original:
                changeMac(interface,
                          interfaces,
                          interfaces[interface]["original"],
                          )
        sys.exit(0)


if __name__ == "__main__":
    main()
    os.execv(__file__, sys.argv)
