from idaapi import *

nums = []

for i in range(25):
    wait_for_next_event(WFNE_SUSP, -1)
    nums.append(get_reg_value('r9'))
    request_continue_process()
    run_requests()

disable_bpt(0x0007FF7515E6AD4)