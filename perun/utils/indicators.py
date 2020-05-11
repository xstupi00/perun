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


def collect(object_path, ignore_list):
    ignore_list = [os.path.abspath(obj) for obj in ignore_list]
    job_matrix, _ = runner.construct_job_matrix(**runner.load_job_info_from_config())
    for command, workloads in job_matrix.items():
        for workload, jobs in workloads.items():
            executable = jobs[0].executable
            object_path = os.path.abspath(object_path or os.path.abspath(executable.cmd))
            fuzz_utils.prepare_workspace(object_path)
            runner.run_prephase_commands("pre_run")
            return_code = utils.run_external_command(shlex.split(executable.to_escaped_string()))
            if return_code != 0:
                raise CalledProcessError(return_code, executable.to_escaped_string())
            stats.add_stats('indicators', ['gcov'], [get_gcov_indicators(object_path, set(ignore_list))])


def get_gcov_indicators(object_path, ignore_list):
    def run_gcov():
        gcov_output = utils.get_stdout_from_external_command(gcov_command)
        return gcov_output

    objects_names = glob.glob(object_path + '/*.o')
    objects_names = [obj for obj in objects_names if obj not in ignore_list]
    if fuzz_utils.get_gcov_version() >= fuzz_utils.GCOV_VERSION_W_INTERMEDIATE_FORMAT:
        gcov_command = ["gcov", "-i", "-m", "-t"] + objects_names
        gcov_indicators = parse_gcov_output(json.loads(json.dumps(run_gcov().splitlines())))
    else:
        gcov_command = ["gcov", "-a", "-m", "-t"] + objects_names
        gcov_indicators = parse_raw_gcov_output(run_gcov().splitlines())

    return gcov_indicators


def parse_gcov_output(output):
    result = {}
    for module in output:
        for file in json.loads(module)["files"]:
            result[file["file"]] = {}
            for function_info in file["functions"]:
                result[file["file"]][function_info["demangled_name"]] = {
                    "blocks": function_info["blocks"],
                    "exec_blocks": function_info["blocks_executed"],
                    "exec_count": function_info["execution_count"],
                    "lines": function_info["end_line"] - function_info["start_line"]
                }
    return result


def parse_raw_gcov_output(gcov_output):
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


def _get_del_functions(head_gcov_stats, prev_gcov_stats):
    del_functions = {}
    for module in head_gcov_stats:
        diff_min_value = min(0, len(head_gcov_stats[module]) - len(prev_gcov_stats.get(module, [])))
        if diff_min_value < 0:
            del_functions[module] = diff_min_value
    return del_functions


def _get_new_functions(head_gcov_stats, prev_gcov_stats):
    new_functions = {}
    for module in head_gcov_stats:
        diff_max_value = max(0, len(head_gcov_stats[module]) - len(prev_gcov_stats.get(module, [])))
        if diff_max_value > 0:
            new_functions[module] = diff_max_value
    return new_functions


def _get_del_blocks(head_gcov_stats, prev_gcov_stats, block_key):
    del_blocks = {}
    for module in head_gcov_stats:
        del_blocks[module] = {}
        for function in head_gcov_stats[module]:
            head_blocks = head_gcov_stats[module][function][block_key]
            prev_blocks = prev_gcov_stats.get(module, {}).get(function, {}).get(block_key, 0)
            diff_min_blocks = min(0, head_blocks - prev_blocks)
            if diff_min_blocks < 0:
                del_blocks[module][function] = diff_min_blocks
    return del_blocks


def _get_new_blocks(head_gcov_stats, prev_gcov_stats, block_key):
    new_blocks = {}
    for module in head_gcov_stats:
        new_blocks[module] = {}
        for function in head_gcov_stats[module]:
            head_blocks = head_gcov_stats[module][function][block_key]
            prev_blocks = prev_gcov_stats.get(module, {}).get(function, {}).get(block_key, 0)
            diff_max_blocks = max(0, head_blocks - prev_blocks)
            if diff_max_blocks > 0:
                new_blocks[module][function] = diff_max_blocks
    return new_blocks


def _get_diff_values_from(head_gcov_stats, prev_gcov_stats, key):
    diff_values = {}
    for module in head_gcov_stats:
        diff_values[module] = {}
        for function in head_gcov_stats[module]:
            head_value = head_gcov_stats[module][function][key]
            prev_value = prev_gcov_stats.get(module, {}).get(function, {}).get(key, 0)
            diff_value = head_value - prev_value
            if diff_value != 0:
                diff_values[module][function] = diff_value
    return diff_values


def evaluate():
    head_gcov_stats = stats.get_stats_of('indicators')['gcov']
    minor_version = '4f391796b7de78a434a2cc7107034603df414905'
    prev_gcov_stats = stats.get_stats_of('indicators', minor_version=minor_version)['gcov']
    del_functions = _get_del_functions(head_gcov_stats, prev_gcov_stats)
    new_functions = _get_new_functions(head_gcov_stats, prev_gcov_stats)
    del_blocks = _get_del_blocks(head_gcov_stats, prev_gcov_stats, 'blocks')
    del_exec_blocks = _get_del_blocks(head_gcov_stats, prev_gcov_stats, 'exec_blocks')
    new_blocks = _get_new_blocks(head_gcov_stats, prev_gcov_stats, 'blocks')
    new_exec_blocks = _get_new_blocks(head_gcov_stats, prev_gcov_stats, 'exec_blocks')
    diff_loc = _get_diff_values_from(head_gcov_stats, prev_gcov_stats, 'lines')
