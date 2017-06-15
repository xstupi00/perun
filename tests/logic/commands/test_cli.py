"""Basic tests for running the cli interface of the Perun

Note that the functionality of the commands themselves are not tested,
this is done in appropriate test files, only the API is tested."""

import pytest

from click.testing import CliRunner

import perun.view.cli as cli

__author__ = 'Tomas Fiedor'


def test_status_correct(pcs_full):
    """Test running perun status in perun directory, without any problems.

    Expecting no exceptions, zero status.
    """
    # Try running status without anything
    runner = CliRunner()
    result = runner.invoke(cli.status, [])
    assert result.exit_code == 0
    assert "On major version" in result.output

    short_result = runner.invoke(cli.status, ['--short'])
    assert short_result.exit_code == 0
    assert len(short_result.output.split("\n")) == 4


@pytest.mark.usefixtures('cleandir')
def test_init_correct():
    """Test running init from cli, without any problems

    Expecting no exceptions, no errors, zero status.
    """
    runner = CliRunner()
    result = runner.invoke(cli.init, ['--vcs-type=git'])
    assert result.exit_code == 0


def test_add_correct(pcs_full, valid_profile_pool):
    """Test running add from cli, without any problems

    Expecting no exceptions, no errors, zero status.
    """
    runner = CliRunner()
    result = runner.invoke(cli.add, ['{}'.format(valid_profile_pool[0])])
    assert result.exit_code == 0


def test_rm_correct(pcs_full, stored_profile_pool):
    """Test running rm from cli, without any problems

    Expecting no exceptions, no errors, zero status
    """
    runner = CliRunner()
    result = runner.invoke(cli.rm, ['{}'.format(stored_profile_pool[1])])
    assert result.exit_code == 0


def test_log_correct(pcs_full):
    """Test running log from cli, without any problems

    Expecting no exceptions, no errors, zero status
    """
    runner = CliRunner()
    result = runner.invoke(cli.log, [])
    assert result.exit_code == 0

    short_result = runner.invoke(cli.log, ['--short'])
    assert short_result.exit_code == 0
    assert len(result.output.split('\n')) > len(short_result.output.split('\n'))


def test_collect_correct(pcs_full):
    """Test running collector from cli, without any problems

    Expecting no exceptions, no errors, zero status
    """
    runner = CliRunner()
    result = runner.invoke(cli.collect, ['-c echo', '-w hello', 'time'])
    print(result.output)
    assert result.exit_code == 0
