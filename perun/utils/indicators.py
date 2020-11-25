"""
TODO
"""
import glob
import json
import os
import re
import shlex
from subprocess import CalledProcessError

import perun.fuzz.evaluate.by_coverage as fuzz_utils
import perun.logic.runner as runner
import perun.logic.stats as stats
import perun.utils as utils

FILE_REGEX = r"^\s+-:\s+\d+:Source:[A-Za-z0-9_-]+\.(c|cc|cpp)$"
FUNCTION_REGEX = r"^function [a-zA-Z_][a-zA-Z0-9_]+ called \d+ returned \d+(?:\.\d+)?% blocks executed \d+(?:\.\d+)?%$"
BLOCK_REGEX = r"^\s*(%{5}|\d+):\s+\d+\-block\s+\d+$"
CALL_REGEX = r"(call)\s+\d+\s+(never\s+executed|returned\s+\d+(?:\.\d+)?%)$"
BRANCH_REGEX = r"^(branch)\s+\d+\s+(never|taken)\s+(executed|\d+|\d+(?:\.\d+)?%)(\s+\(fallthrough\)){0,}$"
FUNCTION_END_REGEX = r"^\s+(#{5}|-|\d+):\s+\d+:}$"
NM_REGEX = r"/_GLOBAL__sub_(D|I)_00100_(0|1)_[A-Za-z_]/"
STAP_SCRIPT_NAME = "func_info.stp"


def collect(object_path, ignore_list):
    ignore_list = [os.path.abspath(obj) for obj in ignore_list]
    job_matrix, _ = runner.construct_job_matrix(**runner.load_job_info_from_config())
    for command, workloads in job_matrix.items():
        for workload, jobs in workloads.items():
            executable = jobs[0].executable
            object_path = os.path.abspath(object_path or os.path.abspath(executable.cmd))
            fuzz_utils.prepare_workspace(object_path)
            runner.run_prephase_commands('pre_run')
            collect_gcov_indicators(executable, object_path, ignore_list)
            collect_stap_indicators(executable)
            collect_nm_indicators(object_path)


def collect_nm_indicators(object_path):
    nm_result = {}
    awk_command = "awk '{ if(($2 == \"T\" || $2 == \"t\") && ($3 !~ " + NM_REGEX + ")) { print $3 }}'"
    for object_file in glob.iglob(object_path + '/*.o'):
        nm_command = "nm " + object_file + " | " + awk_command + " | wc -l"
        nm_output, _ = utils.run_safely_external_command(nm_command)
        nm_result[object_file.split("/")[-1]] = int(nm_output.decode('utf-8'))
    stats.update_stats('indicators', ['nm'], [nm_result])


def collect_stap_indicators(executable):
    stap_script_name = os.path.join(os.path.split(__file__)[0], STAP_SCRIPT_NAME)
    stap_command = \
        'sudo stap ' + stap_script_name + " " + executable.cmd + ' -c ' + '"' + executable.to_escaped_string() + '"'
    stap_output, _ = utils.run_safely_external_command(stap_command)
    stats.update_stats('indicators', ['stap'], [_parse_stap_output(stap_output)])


def _parse_stap_output(stap_output):
    stap_result = {}
    stap_output_list = stap_output.decode('utf-8').split('\n')
    del stap_output_list[-1]
    for function_info in stap_output_list:
        info_list = function_info.split()
        stap_result[info_list[0]] = {
            "called": int(info_list[1]),
            "insns": int(info_list[2]),
            "cycles": int(info_list[3]),
            "branches": int(info_list[4]),
            "cacherefs": int(info_list[5])
        }
    return stap_result


def collect_gcov_indicators(executable, object_path, ignore_list):
    return_code = utils.run_external_command(shlex.split(executable.to_escaped_string()))
    if return_code != 0:
        raise CalledProcessError(return_code, executable.to_escaped_string())
    stats.add_stats('indicators', ['gcov'], [_get_gcov_indicators(object_path, set(ignore_list))])


def _get_gcov_indicators(object_path, ignore_list):
    def run_gcov():
        gcov_output = utils.get_stdout_from_external_command(gcov_command)
        return gcov_output

    objects_names = glob.glob(object_path + '/*.o')
    objects_names = [obj for obj in objects_names if obj not in ignore_list]
    if fuzz_utils.get_gcov_version() >= fuzz_utils.GCOV_VERSION_W_INTERMEDIATE_FORMAT:
        gcov_command = ["gcov", "-i", "-m", "-t"] + objects_names
        gcov_indicators = _parse_gcov_output(json.loads(json.dumps(run_gcov().splitlines())))
    else:
        gcov_command = ["gcov", "-a", "-m", "-t"] + objects_names
        gcov_indicators = _parse_raw_gcov_output(run_gcov().splitlines())

    return gcov_indicators


def _parse_gcov_output(output):
    result = {}
    for module in output:
        module = module[:module.rfind('}') + 1]
        load_files = json.loads(module)["files"] if module.startswith('{') else []
        for file in load_files:
            result[file["file"]] = {}
            for function_info in file["functions"]:
                result[file["file"]][function_info["demangled_name"]] = {
                    "blocks": function_info["blocks"],
                    "exec_blocks": function_info["blocks_executed"],
                    "exec_count": function_info["execution_count"],
                    "lines": function_info["end_line"] - function_info["start_line"]
                }
    return result


def _parse_raw_gcov_output(gcov_output):
    result = {}
    file_name, demangled_name = "", ""
    blocks_executed_perc, lines, execution_count = 0, 0, 0
    blocks = 1
    for line in gcov_output:

        if re.search(FILE_REGEX, line):
            # -: 0:Source: stack.c
            file_name = line.split(":")[-1]  # stack.c (filename)
            result[file_name] = {}

        elif re.search(FUNCTION_REGEX, line):
            # function name called N returned X% blocks executed Y%
            result[file_name][line.split()[1]] = {}  # function name
            execution_count = int(line.split()[3])  # N (function call count)
            blocks_executed_perc = int(line.split()[-1][:-1])  # Y (blocks executed %)

        elif re.search(BLOCK_REGEX, line):
            blocks += 1

        elif re.search(FUNCTION_END_REGEX, line):
            result[file_name][demangled_name] = {
                # TODO: How count the number of the blocks?
                # "blocks": blocks,
                "exec_blocks": blocks_executed_perc / 100,
                "exec_count": execution_count,
                "lines": lines
            }
            blocks_executed_perc, lines, execution_count = 0, 0, 0
            blocks = 1

        elif re.search(CALL_REGEX, line):
            blocks += 1

        elif re.search(BRANCH_REGEX, line) is None:
            lines += 1

    return result


def _get_functions_diff(head_gcov_stats, prev_gcov_stats):
    del_functions, new_functions = {}, {}
    for module in head_gcov_stats:
        new_functions[module] = len({*head_gcov_stats[module]} - {*prev_gcov_stats.get(module, {})})
        del_functions[module] = len({*prev_gcov_stats.get(module, {})} - {*head_gcov_stats[module]})

    del_functions = {k: v for (k, v) in del_functions.items() if v != 0}
    new_functions = {k: v for (k, v) in new_functions.items() if v != 0}
    return del_functions, new_functions


def _get_diffs(head_gcov_stats, prev_gcov_stats, key):
    diffs = {}
    for module in head_gcov_stats:
        diffs[module] = {}
        for function in head_gcov_stats[module]:
            head_blocks = head_gcov_stats[module][function][key]
            prev_blocks = prev_gcov_stats.get(module, {}).get(function, {}).get(key, 0)
            if head_blocks - prev_blocks != 0:
                diffs[module][function] = head_blocks - prev_blocks

    diffs = {k: v for (k, v) in diffs.items() if v != {}}
    return diffs


def evaluate():
    minor_version = 'edf3f97ae2af024708ebb4ac614227327033ca47'
    evaluate_gcov_stats(minor_version)
    evaluate_stap_stats(minor_version)


def evaluate_gcov_stats(minor_version):
    head_gcov_stats = stats.get_stats_of('indicators')['gcov']
    prev_gcov_stats = stats.get_stats_of('indicators', minor_version=minor_version)['gcov']
    del_functions, new_functions = _get_functions_diff(head_gcov_stats, prev_gcov_stats)
    blocks_diff = _get_diffs(head_gcov_stats, prev_gcov_stats, 'blocks')
    exec_blocks_diff = _get_diffs(head_gcov_stats, prev_gcov_stats, 'exec_blocks')
    diff_loc = _get_diffs(head_gcov_stats, prev_gcov_stats, 'lines')


def _get_diff_stats(head_stats, prev_stats):
    diff_stats = {}
    for function in head_stats:
        diff_stats[function] = {
            "called": head_stats[function]["called"] - prev_stats.get(function, {}).get("called", 0),
            "insns": head_stats[function]["insns"] - prev_stats.get(function, {}).get("insns", 0),
            "cycles": head_stats[function]["cycles"] - prev_stats.get(function, {}).get("cycles", 0),
            "branches": head_stats[function]["branches"] - prev_stats.get(function, {}).get("branches", 0),
            "cacherefs": head_stats[function]["cacherefs"] - prev_stats.get(function, {}).get("cacherefs", 0),
        }
    return diff_stats


def evaluate_stap_stats(minor_version):
    head_stap_stats = stats.get_stats_of('indicators')['stap']
    prev_gcov_stats = stats.get_stats_of('indicators', minor_version=minor_version)['stap']
    diff_stats = _get_diff_stats(head_stap_stats, prev_gcov_stats)
