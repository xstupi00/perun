"""
TODO
"""
import git

from termcolor import colored

import perun.utils.exceptions as exceptions
import perun.utils.decorators as decorators
import perun.utils.log as perun_log
import perun.utils.indicators as indicators


def edit_vim_makefile():
    with open("/mnt/cfedb7fe-e4da-4c11-bb07-7bab0d46d61e/vim/src/Makefile", "a") as makefile:
        makefile.write(
            "LDFLAGS=--coverage\n"
            "PROFILE_CFLAGS=-g -O0 -fprofile-arcs -ftest-coverage -DWE_ARE_PROFILING -DUSE_GCOV_FLUSH"
        )


class IndicatorsPredictor:
    def __init__(self, object_path, commit_sha_1, commit_sha_2=None):
        self.repository = git.Repo(search_parent_directories=True)
        self.commit_sha_1 = commit_sha_1 if commit_sha_1 is not None else \
            git.Repo(search_parent_directories=True).head.object.hexsha
        self.commit_sha_2 = commit_sha_2
        self.object_path = object_path
        self.STATIC_THRESHOLD = 0.05
        self.DYNAMIC_THRESHOLD = 0.02
        self.DYNAMIC_WEIGHT = 0.75
        self.static_collector = None
        self.evaluator = None

    def _format_sha(self, sha):
        return colored(self.repository.git.rev_parse(sha, short=6), "red", attrs=["bold"])

    @perun_log.print_elapsed_time
    @decorators.phase_function('nearest-baseline')
    def find_nearest_baseline(self):
        for idx, commit_2 in enumerate(self.repository.iter_commits(self.commit_sha_1)):
            self.commit_sha_2 = commit_2.hexsha
            if self.commit_sha_2 == self.commit_sha_1:
                continue
            self._collect_and_evaluate()
            if self.static_collector.functions_rate >= self.STATIC_THRESHOLD and \
                    self.evaluator.functions_rate >= self.DYNAMIC_THRESHOLD:
                print("Nearest baseline: " + self._format_sha(self.commit_sha_2) + " (skipped " + str(idx) + ")")
                break

    @perun_log.print_elapsed_time
    @decorators.phase_function('relevancy-for-testing')
    def get_relevancy_for_testing(self):
        self._collect_and_evaluate()
        static_relevancy = self.static_collector.functions_rate / self.STATIC_THRESHOLD
        dynamic_relevancy = self.evaluator.functions_rate / self.DYNAMIC_THRESHOLD
        final_relevancy = (static_relevancy * (1 - self.DYNAMIC_WEIGHT) + dynamic_relevancy * self.DYNAMIC_WEIGHT) / 2
        final_relevancy = round(min(final_relevancy, 1.0), 2)
        print(
            "[!] Testing relevancy for commit", self._format_sha(self.commit_sha_2), "wrt. to",
            self._format_sha(self.commit_sha_1), "is:", colored(final_relevancy, "red", attrs=["bold"])
        )

    @perun_log.print_elapsed_time
    @decorators.phase_function('relevancy-for-measuring')
    def get_relevancy_for_measuring(self, function):
        weights = [1/8] * 8
        distribution = []
        self._collect_and_evaluate()
        for diff_iter in [
            self.evaluator.blocks_diff, self.evaluator.exec_blocks_diff,
            self.evaluator.exec_count_diff, self.evaluator.diff_loc
        ]:
            [distribution.append(v) for m, fs in diff_iter.items() for f, v in fs.items() if f == function]
        [distribution.extend([v for v in v.values()]) for f, v in self.evaluator.diff_stats.items() if f == function]
        w_avg = round(sum([distribution[i] * weights[i] for i in range(len(distribution))]) / sum(weights), 2)
        in_static = function in self.static_collector.filtered_functions
        print(
            "[!] Measuring relevancy for function", colored(function, "red", attrs=["bold"]), "for commit",
            self._format_sha(self.commit_sha_2), "wrt. to", self._format_sha(self.commit_sha_1),
            "is:", colored(str(w_avg) + " (" + str(in_static) + ")", "red", attrs=["bold"])
        )

    def _collect_and_evaluate(self):
        self.static_collector = indicators.StaticCollect(self.object_path, self.commit_sha_2, self.commit_sha_1)
        self.static_collector.run()
        self.evaluator = indicators.Evaluate(self.commit_sha_2, self.commit_sha_1, filtering=False)
        self.dynamic_evaluation(self.commit_sha_2)

    def dynamic_evaluation(self, commit_sha_2):
        self._check_and_load_stats(self.commit_sha_1, head=True)
        self._check_and_load_stats(commit_sha_2, head=False)
        self.evaluator.evaluate()

    def _check_and_load_stats(self, commit_sha, head=True):
        gcov_collector = indicators.GCOVCollect(self.object_path, [])
        stap_collector = indicators.StapCollect(self.object_path, [])
        try:
            self.evaluator.load_head_stats(commit_sha) if head else self.evaluator.load_prev_stats(commit_sha)
        except exceptions.StatsFileNotFoundException:
            orig_head = self.repository.head
            self.repository.git.checkout(commit_sha)
            edit_vim_makefile()
            if head and not self.evaluator.head_call_graph:
                indicators.AngrCollect(self.object_path, commit_sha).run()
            elif not head and not self.evaluator.prev_call_graph:
                indicators.AngrCollect(self.object_path, commit_sha).run()
            if head and not self.evaluator.head_gcov_stats:
                gcov_collector.collect()
                stap_collector.collect()
            elif not head and not self.evaluator.prev_gcov_stats:
                gcov_collector.collect()
                stap_collector.collect()
            self.repository.git.checkout(orig_head)
