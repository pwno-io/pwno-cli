#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_debug.py
@Time    : 2021/11/23 23:49:55
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : debug subcommand
'''


import os
import json
from urllib import request as _urlreq
from urllib import error as _urlerr
import re
import tempfile
import threading

import click
from pwn import ELF, context, pause, sleep, which
from pwnlib.atexit import register
from pwnlib.util.safeeval import expr

from ..cli import _set_filename, pass_environ
from ..utils.cli_misc import (CurrentGadgets, get_current_codebase_addr,
                                   get_current_libcbase_addr)
from ..utils.config import try_get_config_data_by_key
from ..utils.misc import ldd_get_libc_path, _Inner_Dict

_NO_TERMINAL = 0


def __recover(f, c):
    with open(f, "wb") as f2:
        f2.write(c)


def _parse_env(ctx, env: str):
    length = len(env)
    # little check
    if (("=" not in env) and (':' not in env)) or (length < 3):
        ctx.abort(msg="debug-command --> Env is invalid, no '=' or ':' in envs, check your env input.")

    # use two points
    res = {}
    key, var = None, None
    groups = re.split(",|;", env)
    for g in groups:
        if "=" in g or ':' in g:
            if '=' in g:
                two = g.split("=", 1)
            else:
                two = g.split(":", 1)
            if len(two) != 2:
                ctx.abort(msg="debug-command --> Env is invalid, wrong format env, check your env input.")
            key, var = two
            key = key.strip()
            var = var.strip()
            res[key] = var
        else:
            ctx.abort(msg="debug-command --> Env is invalid, no '=' or ':' in current env, check your env input.")

    if res:
        ctx.vlog('debug-command --> Set env: {}'.format(res))
    else:
        ctx.vlog2("debug-command --> No valid env exists.")
    return res


def _set_terminal(*args, **kwargs):
    raise RuntimeError("Terminal-based attach is disabled in Pwno-MCP mode")


def _attach_via_mcp(ctx, pid: int, filename: str, script: str, host: str = "127.0.0.1", port: int = 5501):
    """Attach to running process via Pwno-MCP /attach API instead of spawning gdb terminal."""
    # Split script into pre/after commands; send continue-like commands after attach
    pre_cmds = []
    after_cmds = []
    for line in (script or '').splitlines():
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in ("c", "cont", "continue"):  # run after successful attach
            after_cmds.append("continue")
        else:
            pre_cmds.append(cmd)

    payload = {
        "where": filename,
        "pre": pre_cmds or None,
        "pid": int(pid),
        "after": after_cmds or None,
        "script_pid": os.getpid(),
    }

    url = f"http://{host}:{port}/attach"
    data = json.dumps(payload).encode("utf-8")
    req = _urlreq.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")

    ctx.vlog(f"debug-command --> MCP attach POST {url} payload: {payload}")
    try:
        with _urlreq.urlopen(req, timeout=10) as resp:
            resp_body = resp.read().decode("utf-8")
            ctx.vlog2(f"debug-command --> MCP attach response: {resp_body}")
            obj = json.loads(resp_body)
    except _urlerr.HTTPError as e:
        ctx.abort(f"debug-command --> MCP attach HTTPError: {e.code} {e.reason}")
    except _urlerr.URLError as e:
        ctx.abort(f"debug-command --> MCP attach URLError: {e.reason}")
    except Exception as e:
        ctx.abort(f"debug-command --> MCP attach error: {e}")

    if not obj.get("successful"):
        ctx.abort(f"debug-command --> MCP attach failed: {obj}")

    # Set markers similar to pwntools attach return for downstream expectations
    ctx.gift['gdb_pid'] = obj.get("attach", {}).get("pid", pid)
    ctx.gift['gdb_obj'] = 1
    # Emit attach result marker for Pwno-MCP to parse from stdout
    try:
        import sys
        marker = {
            "successful": obj.get("successful"),
            "attach": obj.get("attach"),
        }
        print("PWNCLI_ATTACH_RESULT:" + json.dumps(marker), flush=True)
    except Exception:
        pass
    ctx.vlog("debug-command --> MCP attach success.")


def _check_set_value(ctx, filename, argv, env,
                     gdb_breakpoint, gdb_script, pause_before_main, hook_file, hook_function, gdb_tbreakpoint):
    # set filename
    if not ctx.gift.filename:
        _set_filename(
            ctx, filename, msg="debug-command --> Set 'filename': {}".format(filename))

    # filename is required
    if not ctx.gift.filename:
        ctx.abort("debug-command --> No 'filename'!")
    filename = ctx.gift['filename']
    context.binary = filename
    ctx.gift.elf = ELF(filename, checksec=False)

    # set argv
    if argv:
        argv = argv.strip().split()
    else:
        argv = []

    # all terminal-related logic removed in MCP mode

    # process gdb-scripts
    is_file = False
    script = ''
    script_s = ''
    decomp2dbg_statement = ""

    if gdb_script:
        if os.path.isfile(gdb_script) and os.path.exists(gdb_script):
            is_file = True
        else:
            _script = gdb_script.strip().split(";")
            for _statement in _script:
                _statement = _statement.strip()
                if _statement.startswith("b") and " " in _statement:
                    _left, _right = _statement.split(" ", 1)
                    if "breakpoint".startswith(_left):
                        gdb_breakpoint.append(_right)
                        continue
                    elif "tbreakpoint".startswith(_left):
                        gdb_tbreakpoint.append(_right)
                        continue
                elif _statement.startswith("decompiler ") and len(decomp2dbg_statement) == 0:
                    decomp2dbg_statement = _statement + "\n"
                    continue
                
                script_s += _statement + "\n"
            script_s += '\n'

    _prefix = ["break"] * len(gdb_breakpoint) + \
        ["tbreak"] * len(gdb_tbreakpoint)
    _merge_bps = gdb_breakpoint + gdb_tbreakpoint
    if _merge_bps and len(_merge_bps) > 0:
        for _pre, gb in zip(_prefix, _merge_bps):
            gb = gb.replace(" ", "")
            script += _pre
            if gb.startswith(('0x', "0X")) or gb.isdecimal():
                script += ' *({})\n'.format(gb)
            elif gb.startswith("lb+"): # base is lib.so.6
                script += " *##{}##\n".format(gb[3:])
            elif gb.startswith(('$rebase(', '$_base(')): # base is Program ELF Base
                fi = gb.index('(')
                bi = gb.index(')')
                script += " *###{}###\n".format(gb[fi+1: bi])
            elif gb.startswith('base+'): # base is is Program ELF Base
                script += " *###{}###\n".format(gb[5:])
            elif gb.startswith('bin+'): # base is is Program ELF Base
                script += " *###{}###\n".format(gb[4:])
            elif gb.startswith('b+'): # base is is Program ELF Base
                script += " *###{}###\n".format(gb[2:])
            elif gb.startswith('+'): # base is is Program ELF Base
                script += " *###{}###\n".format(gb[1:])
            elif "+" in gb:
                script += " *####{}####\n".format(gb)
            elif "-" in gb:
                gb = gb.replace("-", "+-")
                script += " *####{}####\n".format(gb)
            else:
                script += ' {}\n'.format(gb)
    
    script = decomp2dbg_statement + script
    script += script_s
    # if gdb_script is file, then open it
    if is_file:
        tmp_fd, tmp_gdb_script = tempfile.mkstemp(text=True)
        ctx.vlog(
            "debug-command --> Create a tempfile used for gdb_script, file path: {}".format(tmp_gdb_script))
        os.close(tmp_fd)
        register(lambda x: os.unlink(x), tmp_gdb_script)
        with open(tmp_gdb_script, 'wt', encoding='utf-8') as f:
            with open(gdb_script, "rt", encoding='utf-8') as f2:
                script += f2.read()
            f.write(script + "\n")
        gdb_script = tmp_gdb_script

    if env:
        env = _parse_env(ctx, env)
        if not env:
            env = None

    if pause_before_main or hook_file or len(hook_function) > 0:
        if which("gcc"):
            file_content = ""
            if hook_file and os.path.exists(hook_file):
                with open(hook_file, "r", encoding="utf-8") as hook_f:
                    file_content += hook_f.read()
            if "#include" in file_content:
                ctx.vlog2(
                    "debug-command --> Please don't introduce any standard library when hook function or define struct, all include statements will be ignored!")
                file_content = file_content.replace("#inclde", "//#include")
            if pause_before_main:
                file_content += "void pause_before_main(void) __attribute__((constructor));\n"
                if context.bits == 64:
                    file_content += """
void pause_before_main()
{
    asm(
        "lea rax,[rsp-0x10];"
        "xor edi, edi;"
        "mov rsi, rax;"
        "xor edx, edx;"
        "inc edx;"
        "xor eax, eax;"
        "syscall;"
        );
}
                    """
                else:
                    file_content += """
void pause_before_main()
{
    asm(
        "lea eax,[esp-0x10];"
        "xor ebx, ebx;"
        "mov ecx, eax;"
        "mov edx, 1;"
        "xor eax, eax;"
        "mov al, 3;"
        "int 0x80;"
        );
}
                    """
            for __func in hook_function:
                _func_retval = 0
                if ":" in __func:
                    __func, _func_retval = __func.split(":")
                elif "=" in __func:
                    __func, _func_retval = __func.split("=")
                file_content += """
int %s()
{
    return %s;
}
                """ % (__func, _func_retval)
            _, tmp_path = tempfile.mkstemp(suffix=".c", text=True)
            with open(tmp_path, "w", encoding="utf-8") as tem_f:
                tem_f.write(file_content)
            cmd = "gcc -g -fPIC -shared {} -o {}.so -masm=intel -nostdlib".format(
                tmp_path, tmp_path)
            if context.bits == 32:
                cmd += " -m32"
            else:
                cmd += " -m64"
            ctx.vlog(
                "debug-command 'pause_before_main/hook_file' --> Execute cmd '{}'.".format(cmd))
            register(lambda x: os.unlink(x) or os.unlink(
                "{}.so".format(x)), tmp_path)
            if not os.system(cmd):
                ctx.vlog(
                    msg="debug-command 'pause_before_main/hook_file' --> Execute last cmd success.")
                if env:
                    env['LD_PRELOAD'] += ":{}.so".format(tmp_path)
                else:
                    env = {'LD_PRELOAD': "{}.so".format(tmp_path)}
            else:
                ctx.verrlog(
                    msg="debug-command 'pause_before_main/hook_file' --> Execute last cmd failed.")
        else:
            ctx.verrlog(
                msg="debug-command 'pause_before_main' --> Cannot find gcc in PATH.")

    # set binary
    ctx.gift['io'] = context.binary.process(
        argv, timeout=ctx.gift['context_timeout'], env=env)
    sleep(0.1)
    if ctx.gift['io'].poll():
        ctx.abort(msg="debug-command --> Process [{}] is not alive now.".format(ctx.gift['io'].proc.pid))
    
    ctx.gift['_elf_base'] = ctx.gift.elf.address or get_current_codebase_addr()
    ctx.gift['process_args'] = argv.copy().insert(0, filename)
    if env:
        ctx.gift['process_env'] = env.copy()

    if not ctx.gift['elf'].statically_linked:
        rp = None
        if env and "LD_PRELOAD" in env:
            for rp_ in env["LD_PRELOAD"].split(";"):
                if "libc" in rp_:
                    rp = rp_
                    break

        if not rp:
            rp = ldd_get_libc_path(filename)

        if rp:
            ctx.gift['libc'] = ELF(rp, checksec=False)
            ctx.gift['libc'].address = 0
            ctx.gift['_libc_base'] = get_current_libcbase_addr()
        else:
            ctx.gift['libc'] = ctx.gift['io'].libc
            ctx.gift['_libc_base'] = ctx.gift['libc'].address
            ctx.gift['libc'].address = 0
            ctx.vlog2('debug-command --> ldd cannot find the libc.so.6 or libc-2.xx.so, and rename your libc file to "libc.so.6" if you add it to LD_PRELOAD')

    ctx.vlog(
        'debug-command --> Set process({}, argv={}, env={})'.format(filename, argv, env))

    # set base+XXX breakpoints
    if "####" in script:
        _pattern = "####([\d\w\+\-\*/]+)####"
        _script = script
        _result = ""
        for _match in re.finditer(_pattern, script, re.I):
            _expr = _match.groups()[0]
            _sym, _off = _expr.split("+", 1)
            _off = int(expr(_off))

            # libc is always PIE enabled...
            if _sym in ctx.gift.libc.sym:
                if ctx.gift.libc.address:  # already have base address
                    _result = hex(ctx.gift.libc.sym[_sym] + _off)
                else:
                    _result = hex(ctx.gift['_libc_base'] +
                                  ctx.gift.libc.sym[_sym] + _off)

            elif _sym in ctx.gift.elf.sym:
                if ctx.gift.elf.pie:  # PIE enabled
                    if ctx.gift.elf.address:
                        _result = hex(ctx.gift.elf.sym[_sym] + _off)
                    else:
                        _result = hex(
                            ctx.gift.elf.sym[_sym] + _off + ctx.gift['_elf_base'])
                else:
                    _result = hex(ctx.gift.elf.sym[_sym] + _off)
            else:
                ctx.verrlog("debug-command --> cannot find symbol '{}' in libc and elf, so the breakpoint will not be set.".format(_sym))
            
            _script = _script.replace("####{}####".format(_expr), _result)
        script = _script

    # have program base-format breakpoints
    if "###" in script:
        if not ctx.gift['elf'].pie:
            ctx.vlog2(
                "debug-command --> set base-format breakpoints while current binary's PIE not enable")
        _pattern = "###([0-9a-fx\+\-\*/]+)###"
        _script = script
        for _match in re.finditer(_pattern, script, re.I):
            _epxr = _match.groups()[0]
            _num = int(expr(_epxr))
            _result = ""
            _result = hex(ctx.gift['_elf_base'] + _num)
        
            _script = _script.replace("###{}###".format(_epxr), _result)
        script = _script

    # process libc base breakpoints
    if "##" in script:
        _pattern = "##([0-9a-fx\+\-\*/]+)##"
        _script = script
        for _match in re.finditer(_pattern, script, re.I):
            _epxr = _match.groups()[0]
            _num = int(expr(_epxr))
            _result = ""
            _result = hex(ctx.gift['_libc_base'] + _num)
        
            _script = _script.replace("##{}##".format(_epxr), _result)
        script = _script

    if script:
        script += "c\n"
        ctx.vlog(
            "debug-command 'gdbscript content':\n{}\n{}{}\n".format("="*20, script, "="*20))
        if is_file:  # 更新gdb file
            with open(gdb_script, "wt", encoding="utf-8") as _f:
                _f.write(script)

    _attach_via_mcp(ctx, ctx.gift['io'].proc.pid, filename, script)

    if pause_before_main:
        pause()  # avoid read from stdin
        ctx.gift.io.send("X")

    # from cli, keep interactive
    if ctx.cli_mode:
        ctx.gift['io'].interactive()
    else:
        res = try_get_config_data_by_key(
            ctx.config_data, "debug", "load_gadget")
        if res and res.strip().lower() in ("true", "yes", "enabled", "enable", "1"):
            threading.Thread(
                target=lambda: CurrentGadgets.reset(), daemon=True).start()


@click.command(name='debug', short_help="Debug the pwn file locally.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.option('-a', '--argv', "argv", type=str, default=None, required=False, show_default=True, help="Argv for process.")
@click.option("-e", '--set-env', "--env", "env", type=str, default=None, required=False, help="The env setting for process, such as LD_PRELOAD setting, split using ',' or ';', assign using ':'.")
@click.option('-p', '--pause', '--pause-before-main', "pause_before_main", is_flag=True, show_default=True, help="Pause before main is called or not, which is helpful for gdb attach.")
@click.option('-f', '-hf', '--hook-file', "hook_file", type=str,  default=None, required=False, help="Specify a hook.c file, where you write some functions to hook.")
@click.option('-H', '-HF', '--hook-function', "hook_function", default=[], type=str, multiple=True, show_default=True, help="The functions you want to hook would be out of work.")
  
@click.option('-b', '-gb', '--gdb-breakpoint', "gdb_breakpoint", default=[], type=str, multiple=True, show_default=True, help="Set gdb breakpoints while gdb is used. Multiple breakpoints are supported.")
@click.option('-T', '-tb', '--gdb-tbreakpoint', "gdb_tbreakpoint", default=[], type=str, multiple=True, show_default=True, help="Set gdb temporary breakpoints while gdb is used. Multiple tbreakpoints are supported.")
@click.option('-s', '-gs', '--gdb-script', "gdb_script", default=None, type=str, show_default=True, help="Set gdb commands like '-ex' or '-x' while gdb-debug is used, the content will be passed to gdb and use ';' to split lines. Besides eval-commands, file path is supported.")
@click.option('-n', '-nl', '--no-log', "no_log", is_flag=True, show_default=True, help="Disable context.log or not.")
@click.option('-P', '-ns', '--no-stop', "no_stop", is_flag=True, show_default=True, help="Use the 'stop' function or not. Only for python script mode.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def cli(ctx, verbose, filename, argv, env, gdb_tbreakpoint,
        gdb_breakpoint, gdb_script, no_log, no_stop, pause_before_main, hook_file, hook_function):
    """FILENAME: The ELF filename.

    \b
    Debug in tmux:
        python3 exp.py debug ./pwn --tmux --gdb-breakpoint malloc -gb 0x400789
        python3 exp.py debug ./pwn --tmux --env LD_PRELOAD:./libc-2.27.so
    """
    ctx.vlog("Welcome to use pwncli-debug command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("debug-command --> Open 'verbose' mode")
    ctx.gift._debug_command = True
    gdb_breakpoint = list(gdb_breakpoint)
    gdb_tbreakpoint = list(gdb_tbreakpoint)
    hook_function = list(hook_function)
    args = _Inner_Dict()
    args.filename = filename
    args.argv = argv
    args.env = env
    args.gdb_breakpoint = gdb_breakpoint
    args.gdb_tbreakpoint = gdb_tbreakpoint
    args.gdb_script = gdb_script
    # terminal-related args removed in MCP mode
    args.pause_before_main = pause_before_main
    args.hook_file = hook_file
    args.hook_function = hook_function
    args.no_log = no_log
    args.no_stop = no_stop

    # log verbose info
    for k, v in args.items():
        ctx.vlog("debug-command --> Get '{}': {}".format(k, v))

    ctx.gift.debug = True
    ctx.gift.no_stop = no_stop

    ll = 'error' if no_log else ctx.gift.context_log_level
    context.update(log_level=ll)
    ctx.vlog("debug-command --> Set 'context.log_level': {}".format(ll))

    # set value
    _check_set_value(ctx, filename, argv, env,
                     gdb_breakpoint, gdb_script, pause_before_main,
                     hook_file, hook_function, gdb_tbreakpoint)