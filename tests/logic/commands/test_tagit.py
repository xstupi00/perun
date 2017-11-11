import pytest
import os

import perun.logic.commands as commands
import perun.logic.config as config
import perun.logic.store as store
import perun.cli as cli

from perun.logic.pcs import PCS
from click.testing import CliRunner


__author__ = 'Tomas Fiedor'


def assert_perun_successfully_init_at(path):
    """Asserts that the perun was successfully initialized at the given path

    Arguments:
        path(str): path
    """
    perun_dir = os.path.join(path, '.perun')
    perun_content = os.listdir(perun_dir)
    assert 'cache' in perun_content
    assert 'objects' in perun_content
    assert 'jobs' in perun_content
    assert os.path.exists(os.path.join(perun_dir, 'local.yml'))
    assert len(perun_content) == 4


def assert_git_successfully_init_at(path, is_bare=False):
    """Asserts that the git was sucessfully initialized at the given path

    Arguments:
        path(str): path to the source of the git directory
    """
    git_dir = os.path.join(path, '' if is_bare else '.git')
    git_content = os.listdir(git_dir)
    assert len(git_content) == 8
    assert 'branches' in git_content
    assert 'hooks' in git_content
    assert 'info' in git_content
    assert 'objects' in git_content
    assert 'refs' in git_content
    assert 'config' in git_content
    assert 'description' in git_content
    assert 'HEAD' in git_content


@pytest.mark.usefixtures('cleandir')
def test_no_params():
    """Test calling 'perun init', which inits PCS without VCS

    Expects to correctly create a directory .perun with basic contents
    """
    pcs_path = os.getcwd()

    commands.init(pcs_path, **{
        'vcs_type': None,
        'vcs_path': None,
        'vcs_params': None
    })

    dir_content = os.listdir(pcs_path)

    # Assert that the directory was correctly initialized
    assert_perun_successfully_init_at(pcs_path)
    assert '.perun' in dir_content
    assert len(dir_content) == 1


@pytest.mark.usefixtures('cleandir')
def test_init():
    """Test correct initialization of tagit, without errors and without any parameters

    Expecting no error, and correctly created .git repository and branch_on_major set to false
    """
    pcs_path = os.getcwd()

    commands.init(pcs_path, **{
        'vcs_type': 'tagit',
        'vcs_path': None,
        'vcs_params': None
    })

    dir_content = os.listdir(pcs_path)

    # Assert everything was correctly set
    assert '.perun' in dir_content
    assert '.git' in dir_content
    assert_perun_successfully_init_at(pcs_path)
    assert_git_successfully_init_at(pcs_path)

    perun_directory = store.locate_perun_dir_on(os.getcwd())
    pcs = PCS(perun_directory)
    bom_key = config.get_key_from_config(pcs.local_config(), 'vcs.branch_on_major')
    assert not bom_key


@pytest.mark.usefixtures('cleandir')
def test_init_branch_on_major():
    """Test correct initialization of tagit, without errors and setting branch_on_major to true

    Expecting no error, and correctly created .git repository and branch_on_major set to true
    """
    pcs_path = os.getcwd()

    commands.init(pcs_path, **{
        'vcs_type': 'tagit',
        'vcs_path': None,
        'vcs_params': {'branch_on_major': True}
    })

    dir_content = os.listdir(pcs_path)

    # Assert everything was correctly set
    assert '.perun' in dir_content
    assert '.git' in dir_content
    assert_perun_successfully_init_at(pcs_path)
    assert_git_successfully_init_at(pcs_path)

    perun_directory = store.locate_perun_dir_on(os.getcwd())
    pcs = PCS(perun_directory)
    bom_key = config.get_key_from_config(pcs.local_config(), 'vcs.branch_on_major')
    assert bom_key


@pytest.mark.usefixtures('cleandir')
def test_init_with_params():
    """Test correct initialization of tagit, with nested .git additional parameters added

    Expecting no error and correctly created .git repository and branch_on_major set to true
    """
    pcs_path = os.getcwd()

    commands.init(pcs_path, **{
        'vcs_type': 'tagit',
        'vcs_path': None,
        'vcs_params': {'branch_on_major': True, 'separate_git_dir': 'dir'}
    })

    dir_content = os.listdir(pcs_path)

    # Assert everything was correctly set
    assert '.perun' in dir_content
    assert '.git' in dir_content
    assert 'dir' in dir_content
    assert_perun_successfully_init_at(pcs_path)
    assert_git_successfully_init_at(os.path.join(pcs_path, 'dir'), True)

    perun_directory = store.locate_perun_dir_on(os.getcwd())
    pcs = PCS(perun_directory)
    bom_key = config.get_key_from_config(pcs.local_config(), 'vcs.branch_on_major')
    assert bom_key


@pytest.mark.usefixtures('cleandir')
def test_init_tagit_correct():
    """Test running init from cli, without any problems

    Expecting no exceptions, no errors, zero status.
    """
    # Assert it is run without problems
    runner = CliRunner()
    dst = str(os.getcwd())
    result = runner.invoke(cli.init, [dst, '--vcs-type=tagit', '--vcs-flag', 'quiet',
                                      '--vcs-flag', 'branch_on_major'])
    assert result.exit_code == 0

    # Assert that it was successfully initialized
    assert_perun_successfully_init_at(dst)
    pcs = PCS(dst)
    bom_key = config.get_key_from_config(pcs.local_config(), 'vcs.branch_on_major')
    assert bom_key
