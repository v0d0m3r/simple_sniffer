# simple_sniffer

This program solves tasks from ./testing_task.txt.

### BUILDING:
Simple_sniffer uses [json-c](https://github.com/json-c/json-c) and [libpcap](https://github.com/the-tcpdump-group/libpcap), so you should install developer version of these packages. For example, for debian:
`$ apt-get install libpcap-dev libjson-c-dev`.
Also this project uses cmake, so you should install it as well.

Next steps:
- `cd /path/to/simple_sniffer/`
- `mkdir build`
- `cd ./build`
- `cmake ../`
- `make`

Executable file will be created in /path/to/simple_sniffer/bin/.

This program was executed on next platforms:
```
Linux raspbian 4.19.66-v7+ armv7l GNU/Linux
Linux debian 4.19.0-4-686-pae i686 GNU/Linux
```
### USAGE:
This program need root privileges!

Simple_sniffer supports settings from arguments of command line and json configure file.
If you execute program without options, program will try to load from `../settings.json`.
Also you can specify a filter almost like tcpdump.

To know which options are used try to `./simple_sniffer -h`

### EXAMPLES:

`./simple_sniffer -i eth0` - grab packets going through eth0

`./simple_sniffer -i eth0 udp dst port 53` - grab packets which destination port is udp#53

`./simple_sniffer -i eth0 ip6`

`./simple_sniffer -c /path/to/config.json` - get settings using configure file
