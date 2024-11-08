from idaapi import *
from idc import *
from idautils import *

class MyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Chall9 Stepper"
    help = "Chall9 Stepper"
    wanted_name = "Chall9 Stepper"
    wanted_hotkey = "`"

    def init(self):
        return MyPlugmod()
    
def match_ins(addr, *ins):
    idx = 0
    while idx < len(ins):
        if print_insn_mnem(addr) != ins[idx]:
            return False
        addr = idc.next_head(addr)
        idx += 1
    return True


class MyPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        addr = get_reg_value("rip")
        if match_ins(addr - 34, 'pop', 'push', 'mov', 'mov', 'lea', 'mov', 'pop'):
            if print_insn_mnem(addr) != 'jmp':
                request_step_until_ret()
                run_requests()
            else:
                request_step_into()
                run_requests()
            return

        if match_ins(addr, 'pop', 'push', 'mov', 'mov', 'lea', 'mov', 'pop'):
            request_run_to(addr + 34)
            run_requests()
        else:
            request_step_into()
            run_requests()
def PLUGIN_ENTRY():
    return MyPlugin()