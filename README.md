# detect_bluekeep.py
Python script to detect bluekeep vulnerability - CVE-2019-0708

Work derived from the Metasploit module written by [@zerosum0x0](https://twitter.com/zerosum0x0)
https://github.com/zerosum0x0/CVE-2019-0708

Added:
- some RDP PDU annotations
- decryption of the server traffic.

## Commandline parameters

```
# ./detect_bluekeep.py
usage: detect_bluekeep.py [-h] [--version] [-d] [-l [LOGFILE]] [-w WORKERS]
                          [host [host ...]]

positional arguments:
  host                  List of targets (addresses or subnets)

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -d, --debug           verbose output
  -l [LOGFILE], --logfile [LOGFILE]
                        log to file
  -w WORKERS, --workers WORKERS
                        number of parallel worker tasks
```

## Running

You may run with a list of IPv4 addresses or hostnames:

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
