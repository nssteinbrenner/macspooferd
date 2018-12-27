# macspooferd

Work in Progress

A Python daemon/CLI tool written for GNU/Linux systems to spoof your MAC address.
The daemon will spoof your MAC address every time you connect/disconnect from a network.
## Getting Stated

### Prerequisites
- Python 3.6+
- iproute2

### Installing
Make sure you have Python3.6+ installed:

    python --version
    Python 3.7.1
    
Test to see if iproute2 is installed:

    ip a s
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
    2: wlp4s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default qlen 1000
    link/ether 74:70:fd:d8:20:14 brd ff:ff:ff:ff:ff:ff
    
Put macspooferd.py and oui.txt in the same directory of your choosing.

### Usage
The CLI tool has various flags as follows:

- -i/--interface - Specifies interfaces on which to spoof the MAC. If this flag isn't used, it will affect all interfaces.
- -v/--vendor - Specifies the vendor of the OUI. If this flag or another flag that specifies OUI isn't used, it will choose a completely random vendor.
- -f/--force - Forces a MAC address change from the daemon if the daemon is running
- -m/--mac - Set the MAC address to specified MAC. Format is XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
- -s/--show - Prints the MAC addresses.
- -e/--ending - Changes only the last three octects, keeping the current OUI.
- -a/--another - Selects a random OUI from the same vendor as the current.
- -r/--random - Sets a fully random MAC address.
- -l/--list - Prints all known vendors. Recommend piping the output or grepping it, as the file is large.
- -d/--daemonize - Run as a daemon.
- -o/--original - Sets MAC address to original and exit.

On first run, it will create the /etc/macspooferd directory. Inside it will store the interfaces present on the system, along with their MAC address, whether the MAC address is the original or not, as well as the original MAC address. It is stored in JSON format.

It retrieves this information by parsing the files in the /sys/class/net/<iface> directory. More documentation on that directory and the files inside can be found here: 

https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net

### Caveats

It isn't quite complete yet. I intended to have the cleanup, etc of the daemon handled by the init system (OpenRC or systemd in particular), but I haven't tested that very extensively yet. At the moment, the daemon aspect works outside of the init system, but you will have to kill it by getting the pid from ps.

Additionally, I haven't found a way to grab the original MAC address if someone has spoofed their MAC address already. As is, if your MAC address has ever been changed, you will have to manually add the original to the /etc/macspooferd/interfaces directory under <iface>["original"]. If it was not able to grab your original MAC, it will be "null" in the JSON file. 

I have only tested the functionality on ArchLinux so far.

### TODO

- Test daemon compatability and cleanup with init systems.
- Test the script on other GNU/Linux distributions.
- Figure out how to find original MAC if it has been spoofed.
- Implement logging system.
- Improve error handling and coordinate it with the logging system.
- Reconsider configuration files format/directory/contents.
- Accept looser MAC address formatting. e.g XX XX XX XX XX XX
