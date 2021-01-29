"""
TODO
"""
import git

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


class NearestBaseline:
    def __init__(self, commit_sha, object_path):
        self.repository = git.Repo(search_parent_directories=True)
        self.commit_sha = commit_sha if commit_sha is not None else \
            git.Repo(search_parent_directories=True).head.object.hexsha
        self.object_path = object_path
        self.STATIC_THRESHOLD = 0.01
        self.DYNAMIC_THRESHOLD = 0.005

    @perun_log.print_elapsed_time
    @decorators.phase_function('nearest-baseline')
    def find(self):
        for idx, commit_2 in enumerate(self.repository.iter_commits(self.commit_sha)):
            if commit_2.hexsha == self.commit_sha:
                continue
            static_collector = indicators.StaticCollect(self.object_path, commit_2.hexsha, self.commit_sha)
            static_collector.run()
            evaluator = indicators.Evaluate(commit_2.hexsha, self.commit_sha)
            self.dynamic_evaluation(evaluator, commit_2.hexsha)
            if static_collector.functions_rate >= self.STATIC_THRESHOLD and \
                    evaluator.functions_rate >= self.DYNAMIC_THRESHOLD:
                print("Nearest baseline: " + commit_2.hexsha + " (skipped " + str(idx) + ")")
                break

    def dynamic_evaluation(self, evaluator, commit_sha_2):
        self._check_and_load_stats(evaluator, self.commit_sha, head=True)
        self._check_and_load_stats(evaluator, commit_sha_2, head=False)
        evaluator.evaluate()

    def _check_and_load_stats(self, evaluator, commit_sha, head=True):
        gcov_collector = indicators.GCOVCollect(self.object_path, [])
        stap_collector = indicators.StapCollect(self.object_path, [])
        try:
            evaluator.load_head_stats(commit_sha) if head else evaluator.load_prev_stats(commit_sha)
        except exceptions.StatsFileNotFoundException:
            orig_head = self.repository.head
            self.repository.git.checkout(commit_sha)
            edit_vim_makefile()
            if head and not evaluator.head_call_graph:
                indicators.AngrCollect(self.object_path, commit_sha).run()
            elif not head and not evaluator.prev_call_graph:
                indicators.AngrCollect(self.object_path, commit_sha).run()
            if head and not evaluator.head_gcov_stats:
                gcov_collector.collect()
                stap_collector.collect()
            elif not head and not evaluator.prev_gcov_stats:
                gcov_collector.collect()
                stap_collector.collect()
            self.repository.git.checkout(orig_head)
