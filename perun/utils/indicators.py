"""
TODO
"""
import abc
import git
import glob
import io
import json
import os
import shlex
import unidiff

from shlex import split
from subprocess import CalledProcessError, Popen, PIPE

import perun.fuzz.evaluate.by_coverage as fuzz_utils
import perun.logic.runner as runner
import perun.logic.stats as stats
import perun.utils as utils
import perun.utils.log as perun_log

from perun.postprocess.regression_analysis.tools import safe_division

STAP_STATS_KEYS = ["called", "insns", "cycles", "branches", "cacherefs"]


class StaticCollect:
    def __init__(self, object_path, commit_sha2, commit_sha1=None):
        self.git_diff = "git diff --ignore-blank-lines --ignore-space-at-eol --ignore-space-change --ignore-all-space "
        self.js_script = os.path.join(os.path.split(__file__)[0], "git_diff.js")
        self.repository = git.Repo(search_parent_directories=True)
        self.object_path = object_path
        self.commit_sha2 = commit_sha2
        self.commit_sha1 = commit_sha1
        self.filtered_functions = []
        self.bash_functions = []
        self.git_functions = []
        self.functions = []
        self.js_changes = {}
        self.HUNK_THRESHOLD = 0.01

    def run(self):
        self._get_functions_list()
        self._get_git_diff_functions()
        self._get_bash_diff_functions()
        self._get_js_diff_functions()
        self.filtered_functions = self.bash_functions + list(set(self.git_functions) - set(self.bash_functions))
        print(self.filtered_functions)

    def _get_functions_list(self):
        regex = r"/_GLOBAL__sub_(D|I)_00100_(0|1)_[A-Za-z_]/"
        awk_command = "awk '{ if(($2 == \"T\" || $2 == \"t\") && ($3 !~ " + regex + ")) { print $3 }}'"
        for object_file in glob.iglob(self.object_path + '/*.o'):
            nm_command = "nm " + object_file + " | " + awk_command
            nm_output, _ = utils.run_safely_external_command(nm_command)
            self.functions.append(nm_output.decode("utf-8").splitlines())
        self.functions = [fun for funcs in self.functions for fun in funcs]

    def _get_js_diff_functions(self):
        # Get git diff between the relevant commits
        git_diff = Popen(split(self.git_diff + self.commit_sha1 + " " + self.commit_sha2), stdout=PIPE)
        js_runner = Popen(split("node " + self.js_script), stdin=git_diff.stdout, stdout=PIPE)
        diff, _ = js_runner.communicate()
        self.js_changes = json.loads(diff.decode("utf-8"))

    def _get_bash_diff_functions(self):
        # Get git diff between the relevant commits
        git_diff = Popen(split(self.git_diff + self.commit_sha1 + " " + self.commit_sha2), stdout=PIPE)
        # Obtains the hunk headers from the diff output
        grep_filter = Popen(split("grep -E '^(@@)'"), stdin=git_diff.stdout, stdout=PIPE)
        # Filter hunk headers that contain open parentheses - probably definition of the function
        grep_filter = Popen(split("grep '('"), stdin=grep_filter.stdout, stdout=PIPE)
        # Filter the lines of the following form: @@ [old-file-range] [new-file-range] @@
        sed_filter = Popen(split("sed 's/@@.*@@//'"), stdin=grep_filter.stdout, stdout=PIPE)
        # Remove the whole content of the line after the open parentheses
        sed_filter = Popen(split("sed 's/(.*//'"), stdin=sed_filter.stdout, stdout=PIPE)
        # Filter the pointer symbol * from pointers
        sed_filter = Popen(split("sed 's/\*//'"), stdin=sed_filter.stdout, stdout=PIPE)
        # Print the last field of the records
        awk_filter = Popen(split("awk '{print $NF}'"), stdin=sed_filter.stdout, stdout=PIPE)
        # Filter duplicate function names
        function = Popen(split("uniq"), stdin=awk_filter.stdout, stdout=PIPE)
        stdout, _ = function.communicate()
        self.bash_functions = stdout.decode("utf-8").split('\n')

    def _get_git_diff_functions(self):
        uni_diff_text = self.repository.git.diff(
            self.commit_sha1, self.commit_sha2,
            ignore_blank_lines=True, ignore_space_at_eol=True, ignore_space_change=True, ignore_all_space=True
        )
        patch_set = unidiff.PatchSet(io.StringIO(uni_diff_text))

        for patched_file in patch_set:
            for hunk in patched_file:
                diff_length = hunk.source_length - hunk.target_length
                if any(m > self.HUNK_THRESHOLD * hunk.source_length for m in [hunk.added, hunk.removed, diff_length]):
                    self.git_functions.append(hunk.section_header)
        self.git_functions = [ref_f for ref_f in self.functions if any(ref_f in f for f in self.git_functions)]


class DynamicCollect:
    def __init__(self, object_path, ignore_list):
        self.object_path = os.path.abspath(object_path)
        self.ignore_list = ignore_list
        self.executable = None
        self.tool = None

    @abc.abstractmethod
    def collect_indicators(self):
        raise NotImplementedError("This method have to implemented in the subclass.")

    @perun_log.print_elapsed_time
    def collect(self):
        job_matrix, _ = runner.construct_job_matrix(**runner.load_job_info_from_config())
        for _, workloads in job_matrix.items():
            for _, jobs in workloads.items():
                self.executable = jobs[0].executable
                object_path = self.object_path or os.path.abspath(self.executable.cmd)
                fuzz_utils.prepare_workspace(object_path)
                runner.run_prephase_commands('pre_run')
                stats.add_stats('indicators', [self.tool], [self.collect_indicators()])


class GCOVCollect(DynamicCollect):
    def __init__(self, object_path, ignore_list):
        super(GCOVCollect, self).__init__(object_path, ignore_list)
        self.tool = 'gcov'
        self.gcov_stats = ['blocks', 'blocks_executed', 'execution_count', 'lines']

    def collect_indicators(self):
        return_code = utils.run_external_command(shlex.split(self.executable.to_escaped_string()))
        if return_code != 0:
            raise CalledProcessError(return_code, self.executable.to_escaped_string())
        return self._get_gcov_indicators()

    def _get_gcov_indicators(self):
        objects_names = glob.glob(self.object_path + '/*.o')
        objects_names = [obj for obj in objects_names if obj not in [os.path.abspath(obj) for obj in self.ignore_list]]
        if fuzz_utils.get_gcov_version() >= fuzz_utils.GCOV_VERSION_W_INTERMEDIATE_FORMAT:
            gcov_command = ["gcov", "-i", "-m", "-t"] + objects_names
            return self._parse_gcov_output(json.loads(json.dumps(
                utils.get_stdout_from_external_command(gcov_command).splitlines()
            )))

    def _parse_gcov_output(self, output):
        result = {}
        for object_file in output:
            object_file_data = object_file[:object_file.rfind('}') + 1]
            modules = json.loads(object_file_data)["files"] if object_file_data.startswith('{') else []
            for module in modules:
                result[module["file"]] = {
                    fun_info["demangled_name"]:
                        {k: fun_info[k] for k in self.gcov_stats[:-1]} for fun_info in module["functions"]
                }
                for fun_info in module["functions"]:
                    result[module["file"]][fun_info["demangled_name"]][self.gcov_stats[-1]] = \
                        fun_info["end_line"] - fun_info["start_line"]
        return result


class StapCollect(DynamicCollect):
    def __init__(self, object_path, ignore_list):
        super(StapCollect, self).__init__(object_path, ignore_list)
        self.tool = 'stap'
        self.stap_keys = STAP_STATS_KEYS
        self.script_name = "func_info.stp"

    def collect_indicators(self):
        script_name = os.path.join(os.path.split(__file__)[0], self.script_name)
        command = 'sudo stap ' + script_name + " " + \
                  self.executable.cmd + ' -c ' + '"' + self.executable.to_escaped_string() + '"'
        output, _ = utils.run_safely_external_command(command)
        return self._parse_output(output)

    def _parse_output(self, stap_output):
        stap_result = {}
        for function_info in stap_output.decode('utf-8').split('\n')[:-1]:
            fun_info_list = function_info.split()
            stap_result[fun_info_list[0]] = {k: int(fun_info_list[i + 1]) for i, k in enumerate(self.stap_keys)}
        return stap_result


class Evaluate:
    def __init__(self, commit_sha2):
        self.diff_stats_keys = STAP_STATS_KEYS
        self.rel_err_thresholds = {"blocks": 0.25, "blocks_executed": 0.25, "execution_count": 0.25, "lines": 0.25}
        self.fun_rate_threshold = 0.25
        self.del_func_threshold = 0.25
        self.new_func_threshold = 0.25
        self.score_threshold = 1
        self.commit_sha2 = commit_sha2
        self.head_stats, self.prev_stats = {}, {}
        self.head_gcov_stats, self.prev_gcov_stats = {}, {}
        self.head_gcov_stats, self.prev_head_stats = {}, {}
        self.new_funcs, self.del_funcs, self.rel_errs = {}, {}, {}
        self.blocks_diff, self.exec_blocks_diff, self.exec_count_diff, self.diff_loc = {}, {}, {}, {}
        self.diff_stats = {}
        self.functions_score = {}

    def evaluate(self):
        self._load_stats()
        self._evaluate_gcov_stats()
        self._evaluate_stap_stats()
        self._build_functions_score()
        print(">> Potential filtered functions:", len(self.functions_score.keys()))
        # print("-f " + " -f ".join(self.functions_score.keys()))

    def _build_functions_score(self):
        def update_score(iterator):
            for function in iterator.keys():
                self.functions_score[function] = self.functions_score.get(function, 0) + 1

        [update_score(functions) for functions in [self.del_funcs, self.new_funcs, self.rel_errs, self.diff_stats]]
        diffs_list = [self.blocks_diff, self.exec_blocks_diff, self.exec_count_diff, self.diff_loc]
        [update_score(v) for mods in diffs_list for k, v in mods.items()]
        self.functions_score = {k: v for (k, v) in self.functions_score.items() if v >= self.score_threshold}

    def _load_stats(self):
        self.head_stats = stats.get_stats_of('indicators')
        self.prev_stats = stats.get_stats_of('indicators', minor_version=self.commit_sha2)
        self.head_gcov_stats, self.prev_gcov_stats = self.head_stats['gcov'], self.prev_stats['gcov']
        self.head_stap_stats, self.prev_stap_stats = self.head_stats['stap'], self.prev_stats['stap']

    def _evaluate_gcov_stats(self):
        self.del_funcs, self.new_funcs, self.rel_errs = self._get_functions_diff()
        self.blocks_diff = self._get_rel_errors_of('blocks')
        self.exec_blocks_diff = self._get_rel_errors_of('blocks_executed')
        self.exec_count_diff = self._get_rel_errors_of('execution_count')
        self.diff_loc = self._get_rel_errors_of('lines')

    def _evaluate_stap_stats(self):
        self.diff_stats = self._get_diff_stats()

    @staticmethod
    def _relative_error(x, y):
        return safe_division(abs(x - y), x) if x > y else safe_division(abs(y - x), y)

    def _get_diff_stats(self):
        diff_stats = {}
        for function in self.head_stap_stats:
            head_func = self.head_stap_stats[function]
            prev_func = self.prev_stap_stats.get(function, {})
            diff_stats[function] = {
                k: self._relative_error(head_func[k], prev_func.get(k, 0)) for k in self.diff_stats_keys
            }
        return diff_stats

    def _get_functions_diff(self):
        # print(">> Overall number of functions im modules:\n", {m: len({*f}) for m, f in self.head_gcov_stats.items()})
        # print(">> Overall number of modules:", len({*self.head_gcov_stats}))
        print(">> Overall number of functions:", sum([len({*f}) for m, f in self.head_gcov_stats.items()]))

        del_functions, new_functions, rel_errors = {}, {}, {}
        for module in self.head_gcov_stats:
            head_functions = self.head_gcov_stats[module]
            prev_functions = self.prev_gcov_stats.get(module, {})
            rel_errors[module] = self._relative_error(len({*head_functions}), len({*prev_functions}))
            new_functions[module] = safe_division(len({*head_functions} - {*prev_functions}), len({*head_functions}))
            del_functions[module] = safe_division(len({*prev_functions} - {*head_functions}), len({*prev_functions}))

        # print(">> Filtered modules by rel_err:",
        #       len({k: v for (k, v) in rel_errors.items() if v < self.fun_rate_threshold}))
        rel_errors = {k: v for (k, v) in rel_errors.items() if v >= self.fun_rate_threshold}

        # print(">> Filtered modules by del_fun:",
        #       len({k: v for (k, v) in del_functions.items() if v < self.del_func_threshold}))
        del_functions = {k: v for (k, v) in del_functions.items() if v >= self.del_func_threshold}

        # print(">> Filtered modules by new_fun:",
        #       len({k: v for (k, v) in new_functions.items() if v < self.new_func_threshold}))
        new_functions = {k: v for (k, v) in new_functions.items() if v >= self.new_func_threshold}
        return del_functions, new_functions, rel_errors

    def _get_rel_errors_of(self, key):
        rel_errors = {}
        for module in self.head_gcov_stats:
            head_module = self.head_gcov_stats[module]
            prev_module = self.prev_gcov_stats.get(module, {})
            rel_errors[module] = {
                f: self._relative_error(head_module[f][key], prev_module.get(f, {}).get(key, 0)) for f in head_module
            }

        # print(">> Filtered functions in modules by " + key + ":")
        # print({m: len({f: v for f, v in s.items() if v < self.rel_err_thresholds[key]}) for m, s in rel_errors.items()})
        return {m: {f: v for f, v in s.items() if v >= self.rel_err_thresholds[key]} for m, s in rel_errors.items()}