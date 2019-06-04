# detect_bluekeep.py
Python script to detect bluekeep vulnerability - CVE-2019-0708 - with TLS/SSL support

Work derived from the Metasploit module written by [@zerosum0x0](https://twitter.com/zerosum0x0)
https://github.com/zerosum0x0/CVE-2019-0708

RC4 taken from https://github.com/DavidBuchanan314/rc4

## Added in version 0.5 - 4.5.2019

The scripts now __supports SSL/TLS security__, which is enabled by default. If you want to use the standard RDP security, use the --notls commandline parameter.

## Added in version 0.1 - 3.5.2019
- some RDP PDU annotations
- decryption of the server traffic.
- properly packetized server to client traffic, including fast path traffic

## Commandline parameters

```
# ./detect_bluekeep.py
usage: detect_bluekeep.py [-h] [--version] [-d] [--notls] [-l [LOGFILE]] [-w WORKERS]
                          [host [host ...]]

positional arguments:
  host                  List of targets (addresses or subnets)

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -d, --debug           verbose output
  --notls               disable TLS security
  -l [LOGFILE], --logfile [LOGFILE]
                        log to file
  -w WORKERS, --workers WORKERS
                        number of parallel worker tasks
```

## Running

You may run with a list of IPv4 addresses:

```
# ./detect_bluekeep.py 192.168.158.241 192.168.158.242 192.168.158.247 192.168.162.73 192.168.162.70
2019-06-03 09:58:01,255 'Starting ./detect_bluekeep.py'
2019-06-03 09:58:01,255 './detect_bluekeep.py 192.168.158.241 192.168.158.242 192.168.158.247 192.168.162.73 192.168.162.70'
2019-06-03 09:58:01,256 'Going to scan 5 hosts, in 300 parallel tasks'
2019-06-03 09:58:01,366 '[-] [192.168.162.73] Status: Unknown'
2019-06-03 09:58:02,222 '[+] [192.168.158.241] Status: Vulnerable'
2019-06-03 09:58:02,887 '[+] [192.168.158.242] Status: Vulnerable'
2019-06-03 09:58:06,262 '[-] [192.168.162.70] Status: No RDP'
2019-06-03 09:58:06,262 '[-] [192.168.158.247] Status: No RDP'
```

or for whole subnets:

```
# ./detect_bluekeep.py 192.168.158.241/24 192.168.162.70/28
```

## License

Apache 2.0
