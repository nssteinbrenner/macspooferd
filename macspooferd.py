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
                    nargs="*",
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

parser.add_argument("-p",
                    "--print",
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

parser.add_argument("-l",
                    "--local",
                    default=False,
                    action="store_true",
                    required=False,
                    help=("Set the locally administered address bit. "
                          "Can only be used with the -r/--random flag."
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
            sys.stderr.write(f"Error accessing /sys/class/net/{interface}/"
                             f"address. File may not exist or be readable.\n"
                             f"{e}\n"
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
            sys.stderr.write(f"Error accessing /sys/class/net/{interface}/"
                             f"addr_assign_type. File may not exist "
                             f"or be readable.\n{e}\n"
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
            sys.stderr.write(f"Error accessing /sys/class/net/{interface}/"
                             f"carrier. File may not exist or be readable.\n"
                             f"{e}\n"
                             )

        if isOriginal is True:
            originMac = mac
        elif os.path.isfile("/etc/macspooferd/interfaces"):
            try:
                with open("/etc/macspooferd/interfaces", "r") as f:
                    storedif = json.load(f)
                    originMac = storedif[interface]["original"]
            except KeyError as e:
                originMac = None
        else:
            originMac = None

        if mac == originMac:
            isOriginal = True

        interfaces[interface] = {"up": up,
                                 "mac": mac,
                                 "mac-is-original": isOriginal,
                                 "original": originMac,
                                 }
    try:
        with open("/etc/macspooferd/interfaces", "r") as f:
            storedif = json.load(f)
    except (FileNotFoundError, NotADirectoryError) as e:
        sys.stderr.write("/etc/macspooferd/interfaces not found. "
                         "Creating file.\n"
                         )
        if os.path.exists("/etc/macspooferd"):
            os.remove("/etc/macspooferd")
            os.mkdir("/etc/macspooferd")
        elif not os.path.isdir("/etc/macspooferd"):
            os.mkdir("/etc/macspooferd")
        with open("/etc/macspooferd/interfaces", "w+") as f:
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
            with open("/etc/macspooferd/interfaces", "w") as f:
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


def genMac(ouiList, vendor, randomMac=False, local=False):
    if randomMac is True:
        bits = []
        for i in range(6):
            bits.append(str(random.randint(0, 1)))

        if local is True:
            bits.append("1")
        else:
            bits.append("0")

        bits.append("0")
        full = "".join(bits)
        firstOctect = str(hex(int(full, 2)))[2:]

        if len(firstOctect) == 1:
            firstOctect = "0" + firstOctect

        firstOctect += ":"

        token_bytes = os.urandom(5)
        mac = binascii.hexlify(token_bytes).decode("ascii")
        mac = (firstOctect + ":".join([mac[i:i+2]
                                       for i in range(0, len(mac), 2)
                                       ]
                                      )
               )
        return mac

    if isinstance(vendor, list):
        vendor = vendor[random.randint(0, len(vendor)-1)]
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
                             "in an unaccepted format or is "
                             "a multicast or broadcast address. "
                             "Accepted formats are:"
                             "\n\tXX:XX:XX:XX:XX:XX "
                             "\n\tXX-XX-XX-XX-XX-XX"
                             )
    except AttributeError as e:
        newMac = interfaces[interface]["mac"]

    oldMac = interfaces[interface]["mac"]

    subprocess.call(["ip", "link", "set", "down", "dev", interface])
    subprocess.call(["ip", "link", "set", "dev", interface, "address", newMac])
    subprocess.call(["ip", "link", "set", "up", "dev", interface])

    sys.stdout.write(f"{interface} MAC changed {oldMac} --> {newMac}\n")

    interfaces = getInterfaces()

    return interfaces


def checkValidMac(mac):
    if int(mac[1], 16) % 2:
        sys.stderr.write(f"MAC {mac} is a multicast address and "
                         "cannot be used as a host MAC address."
                         )
        return False
    elif mac.lower() == "ff:ff:ff:ff:ff:ff":
        sys.stderr.write(f"MAC {mac} is a broadcast address and "
                         "cannot be used as a host MAC address."
                         )
        return False
    elif re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                  mac.lower(),
                  ):
        return True
    else:
        sys.stderr.write(f"MAC {mac} format cannot be parsed.\n")
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
                          ) if proc.decode().strip() != str(os.getpid())
             ]

    if len(procs) == 0:
        sys.stderr.write("Could not find any running Python instances for "
                         "-f/--force.\n"
                         )
        sys.exit(1)

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
                        elif i == "" or i == " ":
                            pass
                        else:
                            currentInterfaces.append(i)

    if foundProc is not True:
        errorMsg = ("Could not find daemon running in processes. "
                    "The -f/--force flag can only be run "
                    "when there is an active daemon running.\n"
                    )
        sys.stderr.write(errorMsg)
        sys.exit(1)

    if len(currentInterfaces):
        updateModTime(currentInterfaces)
        for interface in currentInterfaces:
            sys.stdout.write(f"Forced MAC address change for {interface}\n")
    else:
        updateModTime(interfaces)
        for interface in interfaces:
            sys.stdout.write(f"Forced MAC address change for {interface}\n")


def watcher(interface,
            interfaces,
            ouiList,
            vendor=False,
            ending=False,
            another=False,
            random=False,
            local=False
            ):
    modTime = 0
    if not interface:
        interface = list(interfaces.keys())[:]
    for ifname in interface:
        while True:
            if checkModified(ifname, modTime):
                if ifname not in interfaces.keys():
                    errorMsg = (f"Interface {interface} could "
                                "not be found. Check 'ip a s' "
                                "or 'ip link' output for available "
                                "interfaces.\n"
                                )
                    sys.stderr.write(errorMsg)
                    sys.exit(1)

                elif ending:
                    interfaces = changeMac(ifname,
                                           interfaces,
                                           genEndingMac(ifname,
                                                        interfaces,
                                                        )
                                           )
                elif another:
                    interfaces = changeMac(ifname,
                                           interfaces,
                                           genMac(ouiList,
                                                  checkVendor(ifname,
                                                              interfaces,
                                                              ouiList,
                                                              )
                                                  )
                                           )
                else:
                    interfaces = changeMac(ifname,
                                           interfaces,
                                           genMac(ouiList,
                                                  vendor,
                                                  randomMac=random,
                                                  local=local
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
                            args.print,
                            ]
                           ):
        parser.error("-r/--random can only be used with the following flags:"
                     "\n\t-i/--interface\n\t-d/--daemonize\n\t-l/--local"
                     )

    elif args.mac and any([args.vendor,
                           args.ending,
                           args.another,
                           args.random,
                           args.original,
                           args.force,
                           args.show,
                           args.print,
                           args.daemonize
                           ]
                          ):
        parser.error("-m/--mac can only be used with the following flags:"
                     "\n\t-i/--interface"
                     )

    elif args.ending and any([args.vendor,
                              args.mac,
                              args.another,
                              args.random,
                              args.original,
                              args.force,
                              args.show,
                              args.print,
                              ]
                             ):
        parser.error("-e/--ending can only be used with the following flags:"
                     "\n\t-i/--interface\n\t-d/--daemonize"
                     )

    elif args.another and any([args.vendor,
                               args.mac,
                               args.ending,
                               args.random,
                               args.original,
                               args.force,
                               args.show,
                               args.print,
                               ]
                              ):
        parser.error("-a/--another can only be used with the following flags:"
                     "\n\t-i/--interface\n\t-d/--daemonize"
                     )

    elif args.original and any([args.vendor,
                                args.mac,
                                args.ending,
                                args.random,
                                args.another,
                                args.force,
                                args.show,
                                args.print,
                                args.daemonize
                                ]
                               ):
        parser.error("-o/--original can only be used with the following flags:"
                     "\n\t-i/--interface"
                     )
    elif args.local and not args.random:
        parser.error("-l/--local must be called with -r/--random.")

    elif args.force:
        forceChange(list(interfaces.keys())[:])
        sys.exit(0)

    elif args.print:
        for oui in ouiList:
            print(" ".join(oui).strip())
        sys.exit(0)

    elif args.daemonize:
        retCode = createDaemon()
        watcher(args.interface,
                interfaces,
                ouiList,
                ending=args.ending,
                another=args.another,
                random=args.random,
                local=args.local,
                vendor=args.vendor,
                )
        sys.exit(retCode)

    elif args.interface:
        for interface in args.interface:
            if interface not in interfaces.keys():
                errorMsg = (f"Interface {interface} could not be found."
                            "Check 'ip a s' or 'ip link' output for "
                            "available interfaces.\n"
                            )
                sys.stderr.write(errorMsg)
                sys.exit(1)

            elif args.mac:
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
                                     "in an unaccepted format or is "
                                     "a multicast or broadcast address. "
                                     "Accepted formats are:"
                                     "\n\tXX:XX:XX:XX:XX:XX "
                                     "\n\tXX-XX-XX-XX-XX-XX"
                                     )
            elif args.another:
                changeMac(interface,
                          interfaces,
                          genMac(ouiList,
                                 checkVendor(interface,
                                             interfaces,
                                             ouiList,
                                             )
                                 )
                          )
            elif args.ending:
                changeMac(interface,
                          interfaces,
                          genEndingMac(interface,
                                       interfaces,
                                       )
                          )
            elif args.show:
                print(f'"{interface}" ' +
                      json.dumps(interfaces[interface],
                                 sort_keys=True,
                                 indent=4,
                                 separators=(",\n", ": "),
                                 ) + "\n"
                      )
            elif args.original:
                changeMac(interface,
                          interfaces,
                          interfaces[interface]["original"],
                          )
            else:
                changeMac(interface,
                          interfaces,
                          genMac(ouiList,
                                 args.vendor,
                                 randomMac=args.random,
                                 local=args.local,
                                 )
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
            elif args.another:
                changeMac(interface,
                          interfaces,
                          genMac(ouiList,
                                 checkVendor(interface,
                                             interfaces,
                                             ouiList,
                                             )
                                 )
                          )
            elif args.ending:
                changeMac(interface,
                          interfaces,
                          genEndingMac(interface,
                                       interfaces,
                                       )
                          )
            elif args.original:
                changeMac(interface,
                          interfaces,
                          interfaces[interface]["original"],
                          )
            else:
                changeMac(interface,
                          interfaces,
                          genMac(ouiList,
                                 args.vendor,
                                 randomMac=args.random,
                                 local=args.local,
                                 )
                          )
        sys.exit(0)


if __name__ == "__main__":
    main()
    os.execv(__file__, sys.argv)
