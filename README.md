*This is a fork of RoderickChan's pwncli for LLMs binary research capability with [pwno-mcp](https://oss.pwno.io/pwno-mcp)*

- [Preface](#preface)
- [Introduction](#introduction)
- [Installation](#installation)
- [Usage Modes](#usage-modes)
  - [Command Line Mode](#command-line-mode)
  - [Script Mode](#script-mode)
  - [Library Mode](#library-mode)
- [Tutorial](#tutorial)
- [pwncli Main Command](#pwncli-main-command)
  - [debug Subcommand](#debug-subcommand)
  - [remote Subcommand](#remote-subcommand)
  - [config Subcommand](#config-subcommand)
    - [list Secondary Subcommand](#list-secondary-subcommand)
    - [set Secondary Subcommand](#set-secondary-subcommand)
  - [misc Subcommand](#misc-subcommand)
    - [gadget Secondary Subcommand](#gadget-secondary-subcommand)
    - [setgdb Secondary Subcommand](#setgdb-secondary-subcommand)
  - [patchelf Subcommand](#patchelf-subcommand)
  - [qemu Subcommand](#qemu-subcommand)
  - [template Subcommand](#template-subcommand)
- [Dependencies](#dependencies)
- [Screenshot Examples](#screenshot-examples)
    - [pwncli Example](#pwncli-example)
    - [debug Example](#debug-example)
    - [remote Example](#remote-example)
    - [config Example](#config-example)
    - [misc Example](#misc-example)
    - [patchelf Example](#patchelf-example)
    - [qemu Example](#qemu-example)

> [!NOTE]
> The [deepwiki](https://deepwiki.org/) of pwncli: <https://deepwiki.com/RoderickChan/pwncli>

# Preface

I initially wrote this tool because during the process of learning `pwn`, I often had to repeatedly comment and uncomment statements like `gdb.attach(xxx)`, constantly modify scripts when setting different breakpoints, and also needed to modify scripts when switching from local debugging to remote exploitation.

After getting used to command-line operations, I wondered if I could design a command-line tool that could control certain things through command-line parameters, avoiding the repetitive execution of the above tasks when debugging `pwn` challenges and focusing only on writing exploit scripts. When the idea took shape, I tried to write the first line of code, and thus, `pwncli` was born.

The purpose of a tool is practicality. I believe `pwncli` meets the practicality requirements and can save a lot of time when debugging `pwn` challenges.

If you find `pwncli` useful, please introduce it to fellow `pwners` around you. If you have any questions, please submit an `issue` or contact me at `roderickchan@foxmail.com`, I would be very happy to discuss and communicate with you. If you have good ideas or discover new bugs, feel free to submit `pull requests`.

🏴🏴🏴 Welcome to follow my personal blog. The following two blog sites have the same content and serve as backups for each other. The former is GitHub Pages, and the latter is deployed on a domestic Alibaba Cloud server. The blog is continuously being updated~
- https://roderickchan.github.io
- https://www.roderickchan.cn

# Introduction
[EN](https://github.com/RoderickChan/pwncli/blob/main/README-EN.md) | [ZH](https://github.com/RoderickChan/pwncli/blob/main/README.md) | [API](https://github.com/RoderickChan/pwncli/blob/main/API-DOC.md) | [VIDEO](https://www.youtube.com/watch?v=QFemxI3rnC8)

`pwncli` is a simple and easy-to-use `pwn` challenge debugging and exploitation tool that can improve your speed and efficiency in debugging `pwn` challenge scripts during CTF competitions.

`pwncli` can help you quickly write `pwn` challenge exploitation scripts and achieve convenient switching between local debugging and remote exploitation. `pwncli` supports three usage modes:
- Command line usage mode
- In-script usage mode
- Library import usage mode

The above three modes are referred to as: command line mode, script mode, and library mode, respectively. Among them, command line mode works the same way as other command line tools (such as `ls`, `tar` commands under `linux`), and can be used for local interactive debugging; script mode can wrap your own Python exploitation scripts into command line tools, then call subcommands to execute the required functions; library mode only calls some convenient utility functions to facilitate quick problem solving.

The following usage mode sections will detail the usage methods and techniques of the three modes.

`pwncli` is designed in a main command-subcommand pattern (similar to `git`), and currently has the following (sub)commands:
```
pwncli
    config
        list
        set
    debug
    misc
        gadget
        setgdb
    patchelf
    qemu
    remote
```
Where `pwncli` is the main command, `config/debug/misc/patchelf/qemu/remote` are first-level subcommands, `list/set` are second-level subcommands under `config`, and `gadget/setgdb` are second-level subcommands under `misc`.

`pwncli` supports command prefix matching (similar to `gdb`'s command prefix matching). Usually, you only need to provide the command prefix to successfully call the command. That is, entering `pwncli debug ./pwn`, `pwncli de ./pwn`, and `pwncli d ./pwn` have exactly the same execution effect. However, you must ensure that the prefix does not match two or more subcommands, otherwise a `MatchError` matching error will be thrown.

`pwncli` is extremely easy to extend. You only need to add `cmd_xxx.py` in the `pwncli/commands` directory and write your own subcommand. `pwncli` will automatically detect and load the subcommand. For example, if you want to add a `magic` command, you only need to:
```
1. Add a cmd_magic.py file in the pwncli/commands directory
2. Write the command execution logic in cmd_magic.py
```
When you need to remove the command, you can delete the `cmd_magic` file or rename it to something that doesn't start with `cmd_`.

`pwncli` depends on [click](https://github.com/pallets/click) and [pwntools](https://github.com/Gallopsled/pwntools). The former is an excellent command line writing tool, and the latter is an exploitation library commonly used by `pwners`.

The advantages of `pwncli` can be summarized as:
- Write the script once, use command line to control local debugging and remote exploitation
- Convenient for setting breakpoints and executing other `gdb` commands during debugging
- Easy to extend and customize subcommands
- Many useful built-in commands and functions

# Installation
`pwncli` can be used on both `linux` and `windows`, but usage on `windows` is severely limited, such as the `debug` command being unavailable and the `remote` command being only partially usable. `pwncli` can only be used in a `python3` environment, and compatibility with `python2` is not currently being considered.

It is recommended to use `pwncli` on `ubuntu` systems. In particular, if you understand `WSL` and choose to use `WSL` to solve `pwn` challenges, `pwncli + WSL` would be an excellent choice. The `debug` subcommand has many practical parameters designed for `WSL` systems and implements some interesting features.

If you choose to use `WSL`, please try to ensure that the distribution name is the default `Ubuntu-16.04/Ubuntu-18.04/Ubuntu-20.04/Ubuntu-22.04`. Some options of the `debug` command are closely tied to the default distribution names.

There are two installation methods for `pwncli`. The first is local installation (**strongly recommended**):

```shell
git clone https://github.com/RoderickChan/pwncli.git
cd ./pwncli
pip3 install --editable .
```
After installation, don't forget to add the path where `pwncli` is located to the `PATH` environment variable, which is generally `~/.local/bin`. You can add `export PATH=$PATH:/home/xxx/.local/bin` to the `.bashrc/.zshrc` file in your home directory.

The advantage of this installation method is: when you need to keep `pwncli` updated, you only need to execute `git pull` to use the latest version of `pwncli`.

The second installation method is using `pip3`:
```
pip3 install pwncli
```
The `pwncli` installed this way may not be the latest version and may encounter some already resolved bugs. But please trust me, I will promptly update `pwncli` to `pypi`.

After installation, execute `pwncli --version`. Seeing the version information output indicates successful installation.

# Usage Modes
## Command Line Mode
You can treat `pwncli` as a command line tool, although it is essentially a `python` script. Using `pwncli -h` or `pwncli --help` will get you the command line usage guide. If you want to get the usage guide for a specific subcommand, such as the `debug` command, just enter `pwncli debug -h`.

## Script Mode
In addition to using `pwncli` as a command line tool, you can also wrap your script into a command line tool, and then use this script just like using `pwncli`.
Using script mode is very simple. If your exploitation script is `exp.py`, write in the script:
```python
#!/usr/bin/env python3
from pwncli import *

cli_script() # This function must be called to use script mode
```

Then, entering `python3 exp.py -h` on the command line will give you the same output as `pwncli -h` in command line mode. In particular, if you specify the interpreter path in the first line of the script, you can enter `./exp.py -h` without explicitly typing `python3`.

After that, you can treat `exp.py` as `pwncli` and use all the commands and features that `pwncli` has.

Of course, you can enrich your script to achieve more functionality. When using the `debug` and `remote` commands, you can continue adding to the script:
```python
#!/usr/bin/env python3
from pwncli import *

cli_script() # This function must be explicitly called to use script mode

# You can get many things from gift
io   = gift['io'] # process or remote object
elf  = gift["elf"] # ELF object, ELF("./pwn")
libc = gift.libc # ELF object, ELF("./libc.so.6")

filename  = gift.filename # current filename
is_debug  = gift.debug # is debug or not 
is_remote = gift.remote # is remote or not
gdb_pid   = gift.gdb_pid # gdb pid if debug

# Sometimes the libc provided remotely is different from the local one, replace libc with remote libc when attacking
if gift.remote:
    libc = ELF("./libc.so.6")
    gift['libc'] = libc

# Write exploitation functions here
# ......
io.interactive() # Keep interactive with socket
```
Those familiar with `pwntools` will definitely not be unfamiliar with the above script. Essentially, calling `cli_script()` will parse command line parameters and then place some useful data in `gift`. For example, you can retrieve `io`, which is the `process` or `remote` object from the `pwntools` module, and interact with it.

## Library Mode
Library mode, as the name suggests, is suitable for scenarios where you only need to use some functions or features of `pwncli` without parsing command line parameters. You can use `pwncli` like any other `python` library, for example, write in a script:

```python
from pwncli import *

# Write other script content here
# You can use the interfaces provided in pwncli
context.arch="amd64"
io = process("./pwn")

# If you need to search for libc version and other functions based on offset
# This feature is similar to LibcSearcher but doesn't require local installation, needs internet connection
libc_box = LibcBox()
libc_box.add_symbol("system", 0x640)
libc_box.add_symbol("puts", 0x810)
libc_box.search(download_symbols=False, download_so=False, download_deb=True) # Whether to download locally
read_offset = libc_box.dump("read")

# Get the libc base address of a program by pid
res = get_segment_base_addr_by_proc_maps(pid=10150)
libc_base = res['libc']
heap_base = get_current_heapbase_addr() # Only for local debugging

# Get shellcode
cat_flag = ShellcodeMall.amd64.cat_flag
reverse_tcp = ShellcodeMall.amd64.reverse_tcp_connect(ip="127.0.0.1", port=10001)

# Use some convenient decorators
# Sleep before calling this function
@sleep_call_before(1)
def add():
    pass

# If this function doesn't finish running within 10s, it will throw an exception
@bomber(10)
def del_():
  pass

# API is no longer used
@unused()
def wtf():
  pass

# Search for gadgets
ropper_box = RopperBox()
ropper_box.add_file("libc", "libc.so.6", arch=RopperArchType.x86_64)
pop_rdi_ret = ropper_box.get_pop_rdi_ret()
leav_ret = ropper_box.search_gadget("leave; ret")

# Construct IO_FILE structure
fake_file = IO_FILE_plus_struct()
fake_file.flags = 0xfbad1887
fake_file._mode = 1
fake_file.vtable = 0xdeadbeef
payload = bytes(fake_file)

# Replace payload
payload = "aaaabbbbcccc"
new_payload = payload_replace(payload, {4: "eeee"}) # aaaaeeeecccc

# Get gadgets from currently loaded libc
all_ogs = get_current_one_gadget_from_libc()

# Wrap common io operation functions
# sendline
sl("data")
# sendafter
sa("\n", "data")

# Use current gadgets directly
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

pop_rdi_ret = CurrentGadgets.pop_rdi_ret()

execve_chain = CurrentGadgets.execve_chain(bin_sh_addr=0x11223344)

# There are many other practical interfaces in pwncli
# ......

io.interactive()
```

It's not hard to see that the difference between library mode and command mode usage: just remove `cli_script()`. Note that scripts in library mode are just ordinary `python` scripts and cannot parse command line parameters.

# Tutorial
Video tutorial:
[![pwncli tutorial](https://res.cloudinary.com/marcomontalbano/image/upload/v1674919945/video_to_markdown/images/youtube--QFemxI3rnC8-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://www.youtube.com/watch?v=QFemxI3rnC8 "pwncli tutorial")

`asciinema` version tutorials in order:
- [pwncli tutorial (1)](https://asciinema.org/a/555250)
- [pwncli tutorial (2)](https://asciinema.org/a/555251)
- [pwncli tutorial (3)](https://asciinema.org/a/555252)
- [pwncli tutorial (4)](https://asciinema.org/a/555313)

[![asciicast](https://asciinema.org/a/555250.svg)](https://asciinema.org/a/555250)

[![asciicast](https://asciinema.org/a/555251.svg)](https://asciinema.org/a/555251) 

[![asciicast](https://asciinema.org/a/555252.svg)](https://asciinema.org/a/555252)

[![asciicast](https://asciinema.org/a/555313.svg)](https://asciinema.org/a/555313)

The following is a simple text tutorial.

Before using `pwncli`, it is recommended to master the basic commands of `gdb/tmux` and ensure that you have installed one or more plugins such as `pwndbg/gef/peda`.

Taking the `debug` command in script mode as an example (this is also the most commonly used mode and command).

First enter the `tmux` environment, use `tmux new -s xxx` to enter.

Then write in the script `exp.py`:

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-

from pwncli import *

# use script mode
cli_script()

# get use for obj from gift
io: tube = gift['io'] 
elf: ELF = gift['elf']
libc: ELF = gift['libc']

ia()
```

Then grant the script execution permission, and enter `./exp.py de ./pwn -t` to see the `tmux` debugging window opened.

For programs without `PIE`, the way to set breakpoints is:

```shell
./exp.py de ./pwn -t -b 0x400088a # Set breakpoint at 0x400088a

./exp.py de ./pwn -t -b malloc -b free # Set 2 breakpoints
```

For programs with `PIE`, the way to set breakpoints is:

```shell
./exp.py de ./pwn -t -b b+0xafd # Set breakpoint at 0xafd

./exp.py de ./pwn -t -b malloc -b free -b b+0x101f # Set 3 breakpoints

./exp.py de ./pwn -t -b malloc+0x10 # Set breakpoint at malloc+0x10, first look for malloc symbol in libc, then look for malloc symbol in elf
```

To `hook` certain functions, such as `ptrace`:

```shell
./exp.py de ./pwn -H ptrace -H alarm:1   # Hook ptrace, default return 0; hook alarm, return value is 1

./exp.py de ./pwn -h ./hook.c # Specify after writing your own hook.c
```

When debugging with an `ubuntu` virtual machine with a desktop, you can choose to pop up a `gnome` window:

```shell
./exp.py de ./pwn -g -b 0x400088a # Set breakpoint at 0x400088a

./exp.py de ./pwn -g -s "directory /usr/glibc/glibc-2.31/malloc" # Specify source code debugging directory
```

After debugging the script, you need to attack remotely:

```
./exp.py re ./pwn 127.0.0.1:13337
```

# pwncli Main Command
Option descriptions:

- `flag` option: Enabling this option means turning it on, like `-a` in `ls -a` is a `flag` option
- Multiple choice: Can specify multiple values, like `-x y1 -x y2` can pass `y1` and `y2` to the `x` option
- Multiple usage methods: Like `-x --xxx --xxx-xx`, then using `-x` or `--xxx` or `--xxx-xxx` are all valid

The `pwncli` command is the main command. Entering `pwncli -h` will give you the following output:

```
Usage: pwncli [OPTIONS] COMMAND [ARGS]...

  pwncli tools for pwner!

  For cli:
      pwncli -v subcommand args
  For python script:
      script content:
          from pwncli import *
          cli_script()
      then start from cli: 
          ./yourownscript -v subcommand args

Options:
  -f, --filename TEXT  Elf file path to pwn.
  -v, --verbose        Show more info or not.
  -V, --version        Show the version and exit.
  -h, --help           Show this message and exit.

Commands:
  config    Get or set something about config data.
  debug     Debug the pwn file locally.
  misc      Misc of useful sub-commands.
  patchelf  Patchelf executable file using glibc-all-in-one.
  qemu      Use qemu to debug pwn, for kernel pwn or arm/mips arch.
  remote    Pwn remote host.
  test      Test command.
```

**Options**:

```
-f  Optional  Path to the pwn file to be debugged, e.g., ./pwn. If specified here, it doesn't need to be specified in debug/remote subcommands.
-v  Optional  Flag option, off by default. When enabled, it will show log information. If you need to show more information, you can enter -vv.
-V         View version information.
-h         View help.
```

**Commands** (subcommands under `pwncli`):

```
config     Operate pwncli configuration file, configuration file path is ~/./pwncli.conf.
debug      Most commonly used subcommand, used for local debugging of pwn challenges.
misc       Miscellaneous commands, contains some useful subcommands.
patchelf   Quickly execute patchelf to debug different versions of glibc.
qemu       Use qemu to debug pwn challenges, for kernel pwn or other architectures.
remote     Most commonly used subcommand, used for remote exploitation of targets.
test       Test command, no other use.
```

## debug Subcommand
Entering `pwncli debug -h` will give you the following help documentation:

```
Usage: pwncli debug [OPTIONS] [FILENAME]

  FILENAME: The ELF filename.

  Debug in tmux:
      python3 exp.py debug ./pwn --tmux --gdb-breakpoint malloc -gb 0x400789

Options:
  --argv TEXT                     Argv for process.
  -e, --set-env, --env TEXT       The env setting for process, such as
                                  LD_PRELOAD setting, split using ',' or ';',
                                  assign using '=' or ':'.
  -p, --pause, --pause-before-main
                                  Pause before main is called or not, which is
                                  helpful for gdb attach.  [default: False]
  -f, -hf, --hook-file TEXT       Specify a hook.c file, where you write some
                                  functions to hook.
  -H, -HF, --hook-function TEXT   The functions you want to hook would be out
                                  of work.
  -t, --use-tmux, --tmux          Use tmux to gdb-debug or not.  [default:
                                  False]
  -w, --use-wsl, --wsl            Use wsl to pop up windows for gdb-debug or
                                  not.  [default: False]
  -m, -am, --attach-mode [auto|tmux|wsl-b|wsl-u|wsl-o|wsl-wt|wsl-wts]
                                  Gdb attach mode, wsl: bash.exe | wsl:
                                  ubuntu1x04.exe | wsl: open-wsl.exe | wsl:
                                  wt.exe wsl.exe  [default: auto]
  -u, -ug, --use-gdb              Use gdb possibly.  [default: False]
  -g, -gt, --gdb-type [auto|pwndbg|gef|peda]
                                  Select a gdb plugin.
  -b, -gb, --gdb-breakpoint TEXT  Set gdb breakpoints while gdb-debug is used,
                                  it should be a hex address or '\$rebase'
                                  addr or a function name. Multiple
                                  breakpoints are supported.
  -s, -gs, --gdb-script TEXT      Set gdb commands like '-ex' or '-x' while
                                  gdb-debug is used, the content will be
                                  passed to gdb and use ';' to split lines.
                                  Besides eval-commands, file path is
                                  supported.
  -n, -nl, --no-log               Disable context.log or not.  [default:
                                  False]
  -P, -ns, --no-stop              Use the 'stop' function or not. Only for
                                  python script mode.  [default: False]
  -v, --verbose                   Show more info or not.
  -h, --help                      Show this message and exit.
```

The `debug` subcommand is the most commonly used subcommand and has the most parameters designed for it. The meaning and usage of each parameter will be explained in detail below.

**Arguments**:

```
FILENAME  Optional  Path to the local pwn file to debug, can also be set via the -f option in the pwncli main command; if not set in pwncli main command, it must be set here.
```

**Options**:

```
--argv  Optional      Arguments passed to the process constructor besides the file path.
-e      Optional      Set startup environment variables, e.g., LD_PRELOAD=./libc.so.6;PORT_ENV:1234,IP_ADDR=localhost, data will be passed to the env parameter of the process constructor. Environment variables will be uniformly converted to uppercase. LD_PRELOAD can be abbreviated as PRE=./libc.so.6.
-p      Optional      Flag option, effective after enabling gdb, off by default. When enabled, a getchar() function will be executed before the main function, facilitating gdb attach for debugging, avoiding the problem of gdb.attach failure sometimes. Essentially compiles and generates a .so file and sets it as the LD_PRELOAD environment variable, executing the getchar function in the init section.
-f      Optional      Effective after enabling gdb, your custom hook.c file, which will be compiled as .so and set as the LD_PRELOAD environment variable.
-H      Optional      Multiple choice, effective after enabling gdb. Select function names to hook, such as alarm function, hooked functions will directly return 0, supports multiple options, i.e., -H alarm -H ptrace.
-t      Optional      Flag option, off by default. When enabled, uses tmux to open gdb with vertical split screen. Must ensure you're in a tmux environment before enabling, otherwise an error will occur.
-w      Optional      Flag option, off by default. When enabled, uses wsl mode to open gdb with pop-up window debugging. Must ensure you're in a wsl distribution environment before enabling, otherwise an error will occur.
-m      Optional      Effective after enabling gdb, default is auto. Specify the gdb debugging mode. auto: automatic selection; tmux: effective after enabling -t; wsl-b: effective after enabling -w, uses bash.exe pop-up; wsl-u: effective after enabling -w, uses ubuntu1x04.exe pop-up, provided it's added to the Windows host PATH environment variable; wsl-o: effective after enabling -w, uses open-wsl.exe pop-up, need to download from https://github.com/mskyaxl/wsl-terminal and add it to Windows PATH environment variable; wsl-wt: effective after enabling -w, uses windows-terminal pop-up, needs Windows Terminal installed; wsl-wts: effective after enabling -w, uses Windows Terminal split screen debugging, ensure version is at least 1.11.3471.0.
-u      Optional      Flag option, off by default. When enabled, will use gdb for debugging as much as possible.
-g      Optional      Effective after enabling gdb, default is auto. Select gdb plugin type. Prerequisites are having gef, peda, pwndbg all installed in home directory. auto: uses ~/.gdbinit configuration, otherwise uses pwncli/conf/.gdbinit-xxx configuration.
-b      Optional      Multiple choice, effective after enabling gdb. Set breakpoints in gdb. Three ways to set: 1) Function address, -b 0x401020 or -b 4198432; 2) Function name, -b malloc; 3) Offset relative to PIE base, suitable for PIE-enabled scenarios, -b base+0x4f0 or -b b+0x4f0 or -b \$rebase(0x4f0) or -b \$_base(0x4f0), only supports gef and pwndbg plugins. Supports setting multiple breakpoints, e.g., -b malloc -b 0x401020.
-s      Optional      Effective after enabling gdb. Can be file path or statement. If statement, will be executed in gdb after setting, each sub-statement separated by semicolon ;, e.g., -s "directory /usr/src/glibc/glibc-2.27/malloc;b malloc"; if file path, will execute each line in the file sequentially in gdb.
-n      Optional      Flag option, off by default. Set pwntools to no log information. If this option is enabled, pwntools log will be turned off.
-P      Optional      Flag option, off by default. Disable stop function. The stop function waits for input and prints current information, facilitating gdb debugging. After enabling this option, the stop function will be disabled.
-v      Optional      Flag option, off by default. When enabled, will show log information. If you need to show more information, you can enter -vv.
-h      Optional      View help.
```

## remote Subcommand

Entering `pwncli remote -h` gives the following help:

```
Usage: pwncli remote [OPTIONS] [FILENAME] [TARGET]

  FILENAME: ELF filename.

  TARGET: Target victim.

  For remote target:
      pwncli -v remote ./pwn 127.0.0.1:23333 -up --proxy-mode default
  Or to specify the ip and port:
      pwncli -v remote -i 127.0.0.1 -p 23333

Options:
  -i, --ip TEXT                   The remote ip addr.
  -p, --port INTEGER              The remote port.
  -P, -up, --use-proxy            Use proxy or not.  [default: False]
  -m, -pm, --proxy-mode [undefined|notset|default|primitive]
                                  Set proxy mode. undefined: read proxy data
                                  from config data(do not set this type in
                                  your file); notset: not use proxy; default:
                                  pwntools context proxy; primitive: pure
                                  socks connection proxy.  [default:
                                  undefined]
  -n, -nl, --no-log               Disable context.log or not.  [default:
                                  False]
  -v, --verbose                   Show more info or not.
  -h, --help                      Show this message and exit.
```

`remote` is also a frequently used subcommand for remote exploitation of targets. After debugging the script locally, you only need to replace the `debug` command with `remote` and set the parameters to start attacking the target without changing the script.

**Arguments**:

```
FILENAME  Optional    Path to the local pwn file to debug, can also be set via the -f option in the pwncli main command; after setting, you won't need to manually set context.arch, context.os, etc.
TARGET    Optional    Target machine; must be specified if not using -i and -p parameters. Format: ip:port, e.g., 127.0.0.1:1234.
```

**Options**:

```
-i  Optional    Set target machine, can be domain name or IP address. If not set in TARGET parameter, must be set here. If configured in ~/.pwncli.conf, will read target IP address from config file as default.
-p  Optional    Set target machine port. If TARGET parameter is not set, must be set here.
-P  Optional    Flag option, off by default. When enabled, will use proxy.
-m  Optional    Effective after enabling proxy. Will read proxy configuration from ~/.pwncli.conf. undefined: undefined proxy; notset: don't use proxy; default: use pwntools context.proxy setting; primitive: use socks setting.
-n  Optional    Flag option, off by default. Set pwntools to no log information. If this option is enabled, pwntools log will be turned off.
-v  Optional    Flag option, off by default. When enabled, will show log information. If you need to show more information, you can enter -vv.
-h              View help.
```

## config Subcommand

The `config` subcommand is mainly used to operate the `pwncli` configuration file. The configuration file path is `~/.pwncli.conf`. Its guidance is:

```
Usage: pwncli config [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  list  List config data.
  set   Set config data.
```

**Options**:

```
-h    View help.
```

**Commands**:

```
list  View configuration file data.
set   Set configuration file data.
```

### list Secondary Subcommand

Entering `pwncli config list -h` gives the following output:

```
Usage: pwncli config list [OPTIONS] [LISTDATA]

  LISTDATA: List all data or example data or section names.

Options:
  -s, -sn, --section-name TEXT  List config data by section name.
  -h, --help                    Show this message and exit.
```

**Arguments**:

```
LISTDATA  Optional    Type of data to list. all: list all configuration file data; example: list example configuration file data; section: list sections in configuration file data; other values are illegal.
```

**Options**:

```
-s  Optional    Multiple choice. List data by section name.
-h              View help.
```

### set Secondary Subcommand

Entering `pwncli config set -h` gives the following output:

```
Usage: pwncli config set [OPTIONS] [CLAUSE]

Options:
  -s, -sn, --section-name TEXT  Set config data by section name.
  -h, --help                    Show this message and exit.
```

**Arguments**:

```
CLAUSE  Required    Setting statement, format is key=value.
```

**Options**:

```
-s  Optional    Set data by section.
-h              View help.
```

## misc Subcommand

The `misc` subcommand is a collection of miscellaneous commands, meaning it contains many secondary subcommands, each with different functionality.

Entering `pwncli misc -h` gives help information:

```
Usage: pwncli misc [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  gadget  Get all gadgets using ropper and ROPgadget, and then store them in
          files.
  setgdb  Copy gdbinit files from and set gdb-scripts for current user.
```

**Options**:

```
-h    View help.
```

**Commands**:

```
gadget    Use ropper and ROPgadget tools to get all gadgets and store them locally.
setgdb    Copy pwncli/conf/.gdbinit-xxx configuration files to home directory. Prerequisites for using this command are downloading gef, peda, pwndbg, Pwbgdb plugins to home directory.
```

### gadget Secondary Subcommand

Entering `pwncli misc gadget -h` gives help information:

```
Usage: pwncli misc gadget [OPTIONS] [FILENAME]

Options:
  -a, --all, --all-gadgets     Get all gadgets and don't remove duplicates.
                               [default: False]
  -d, --dir, --directory TEXT  The directory to save files.
  -h, --help                   Show this message and exit.
```

**Arguments**:

```
FILENAME  Required    Binary path to get gadgets from.
```

**Options**:

```
-a  Optional    Flag option, off by default. When enabled, will not remove duplicate gadgets.
-d  Optional    Path to save gadgets files. If not specified, defaults to current directory.
-h              View help.
```

### setgdb Secondary Subcommand

Entering `pwncli misc setgdb -h` gives help information:

```
Usage: pwncli misc setgdb [OPTIONS]

Options:
  -g, --generate-script  Generate the scripts of gdb-gef/gdb-pwndbg/gdb-peda
                         in /usr/local/bin or not.  [default: False]
  --yes                  Confirm the action without prompting.
  -h, --help             Show this message and exit.
```

**Options**:

```
-g      Optional    Flag option, off by default. When enabled, will generate three shell scripts in /usr/local/bin: gdb-gef, gdb-peda, gdb-pwndbg. This option needs to be used with sudo.
--yes   Confirmation    Enter y for the command to take effect.
-h                  View help.
```

The content of `gdb-pwndbg` is:

```
#!/bin/sh
cp ~/.gdbinit-pwndbg ~/.gdbinit
exec gdb "$@"
```

## patchelf Subcommand

Use `patchelf` to modify the `libc.so.6` and `ld.so` used by binary files. Prerequisites for using this command are having `patchelf` and `glibc-all-in-one` installed, and placing various version library files in `glibc-all-in-one/libs`. This path can be configured in the configuration file.

Entering `pwncli patchelf -h` gives help information:

```
Usage: pwncli patchelf [OPTIONS] FILENAME LIBC_VERSION

  FILENAME: ELF executable filename.

  LIBC_VERSION: Libc version.

  pwncli patchelf ./filename 2.29 -b

Options:
  -b, --back, --back-up           Backup target file or not.
  -f, --filter, --filter-string TEXT
                                  Add filter condition.
  -h, --help                      Show this message and exit.
```

**Arguments**:

```
FILENAME  Required    File path to patch.
```

**Options**:

```
-b  Optional    Flag option, off by default. When enabled, will backup the file before executing patchelf command, recommended to enable.
-f  Optional    Filter, set filter conditions. E.g., -f 2.23 will match glibc library version 2.23.
-h              View help.
```

## qemu Subcommand

This subcommand facilitates using `qemu` for debugging other architectures `arm/mips` files and `kernel pwn` debugging. The usage of this command is very similar to the `debug` subcommand, with many options and parameters the same as the `debug` subcommand and used in the same way. Before using this subcommand, please ensure that `qemu` and required dependencies are installed.

Entering `pwncli qemu -h` gives help information:

```
Usage: pwncli qemu [OPTIONS] [FILENAME] [TARGET]

  FILENAME: The binary file name.

  TARGET:  remote_ip:remote_port.

  Debug mode is default setting, debug with qemu:
      pwncli qemu ./pwn -S --tmux
      pwncli qemu ./pwn -L ./libs --tmux
  Specify qemu gdb listen port: 
      pwncli qemu ./pwn -L ./libs -S -p 1235
  Attack remote:
      pwncli qemu ./pwn 127.0.0.1:10001
      pwncli qemu ./pwn -r -i 127.0.0.1 -p 10001

Options:
  -d, --debug, --debug-mode       Use debug mode or not, default is opened.
  -r, --remote, --remote-mode     Use remote mode or not, default is debug
                                  mode.  [default: False]
  -i, --ip TEXT                   The remote ip addr or gdb listen ip when
                                  debug.
  -p, --port INTEGER              The remote port or gdb listen port when
                                  debug.
  -L, --lib TEXT                  The lib path for current file.
  -S, --static                    Use tmux to gdb-debug or not.  [default:
                                  False]
  -l, -ls, --launch-script TEXT   The script to launch the qemu, only used for
                                  qemu-system mode and the script must be
                                  shell script.
  -t, --use-tmux, --tmux          Use tmux to gdb-debug or not.  [default:
                                  False]
  -w, --use-wsl, --wsl            Use wsl to pop up windows for gdb-debug or
                                  not.  [default: False]
  -g, --use-gnome, --gnome        Use gnome terminal to pop up windows for
                                  gdb-debug or not.  [default: False]
  -G, -gt, --gdb-type [auto|pwndbg|gef|peda]
                                  Select a gdb plugin.
  -b, -gb, --gdb-breakpoint TEXT  Set gdb breakpoints while gdb-debug is used,
                                  it should be a hex address or a function
                                  name. Multiple breakpoints are supported.
  -s, -gs, --gdb-script TEXT      Set gdb commands like '-ex' or '-x' while
                                  gdb-debug is used, the content will be
                                  passed to gdb and use ';' to split lines.
                                  Besides eval-commands, file path is
                                  supported.
  -n, -nl, --no-log               Disable context.log or not.  [default:
                                  False]
  -P, -ns, --no-stop              Use the 'stop' function or not. Only for
                                  python script mode.  [default: False]
  -v, --verbose                   Show more info or not.  [default: 0]
  -h, --help                      Show this message and exit.
```

**Arguments**:

```
FILENAME    Optional    Binary file path to debug, can be ko for kernel pwn
TARGET      Optional    IP and port for remote attack, either FILENAME or TARGET must be specified
```

**Options**:

```
-d    Optional    Flag option, enabled by default. This option generally doesn't need to be explicitly specified.
-r    Optional    Flag option, off by default. Can be explicitly specified to indicate remote attack.
-i    Optional    Target IP address in remote mode; gdb listen IP address in debug mode.
-p    Optional    Target port in remote mode; gdb listen port in debug mode.
-L    Optional    Dynamic library directory under qemu-user, will be passed to qemu. If not specified, will search under /usr directory.
-S    Optional    Flag option, off by default. When enabled, will use qemu-xxxx-static.
-l    Optional    Qemu launch script path, convenient for kernel pwn debugging.
-t    Optional    Flag option, off by default. When enabled, uses tmux to open gdb-multiarch debugging.
-w    Optional    Flag option, off by default. When enabled, uses wsl debugging.
-g    Optional    Flag option, off by default. When enabled, uses gnome-terminal debugging.
-G    Optional    Explicitly specify the gdb plugin to use for this debugging session: pwndbg/peda/gef.
-b    Optional    Set breakpoints, similar to debug subcommand settings, but doesn't support PIE-type breakpoints.
-s    Optional    Set gdb commands, similar to debug subcommand settings, supports statements or file paths.
-n    Optional    Flag option, off by default. When enabled, sets pwntools log level to error.
-P    Optional    Flag option, off by default. When enabled, disables the stop function.
```

## template Subcommand

This subcommand facilitates generating various exploitation template script files, including exploitation scripts using `pwncli`'s command line mode and script mode, as well as templates needed for using native `pwntools`. The templates define code related to local debugging and remote exploitation, and provide commonly used abbreviation functions like `sa/sla/r/rl`.

Entering `pwncli template -h` gives help information:

```
Usage: pwncli template [OPTIONS] [FILETYPE]

  FILETYPE: The type of exp file

  pwncli template cli
  pwncli template lib
  pwncli template pwn

Options:
  -h, --help  Show this message and exit.
```

Where the `cli` type template uses `pwncli`'s script mode, the `lib` type template uses library mode, and the `pwn` type template directly uses raw `pwntools` to build without using `pwncli`.

# Dependencies

The dependency list for `pwncli` is as follows:

```
click   
ropper  
pwntools  
```

# Screenshot Examples

### pwncli Example

![image-20220226232019621](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232019621.png)

### debug Example

`pwncli -vv debug ./test`:

![image-20220226232116090](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232116090.png)

`pwncli -vv debug ./test -t`:

![image-20220226232356871](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232356871.png)

`pwncli de ./test -t -b main`:

![image-20220226232710687](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232710687.png)

At this point, the breakpoint didn't catch:

`pwncli de ./test -p -t -b main`:

![image-20220226232858593](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232858593.png)

![image-20220226232946892](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232946892.png)

`pwncli de ./test -H puts`:

![image-20220226233434698](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226233434698.png)

`pwncli de ./test -t -s "vmmap;b main"`:

![image-20220226233628316](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226233628316.png)

`pwncli de ./test -w`:

![image-20220226233900484](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226233900484.png)

`pwncli de ./test -w -m wsl-u`:

![image-20220226234010903](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234010903.png)

`pwncli de ./test -w -m wsl-wts`:

![image-20220226234057770](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234057770.png)

`pwncli de ./test -t -g pwndbg`:

![image-20220226234152877](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234152877.png)

`pwncli de ./test -u`:

![image-20220226234307876](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234307876.png)

### remote Example

`pwncli re ./test 127.0.0.1:10001`:

![image-20220226235042604](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235042604.png)

`pwncli -vv re ./test -i 127.0.0.1 -p 10001`:

![image-20220226235158851](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235158851.png)

`pwncli -vv re 127.0.0.1:10001`:

![image-20220226235248653](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235248653.png)

### config Example

`pwncli config list example`:

![image-20220226235423624](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235423624.png)

### misc Example

`pwncli misc gadget ./test`:

![image-20220226235602674](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235602674.png)

`sudo pwncli misc setgdb -g`:

![image-20220226235738869](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235738869.png)

### patchelf Example

`pwncli patchelf ./test -b 2.31`:

![image-20220226235851991](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235851991.png)

### qemu Example

**TODO**
