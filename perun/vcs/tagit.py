import perun.vcs
import perun.logic.config as config

from perun.logic.pcs import PCS

__author__ = 'Tomas Fiedor'


def _init(pcs_path, vcs_path, vcs_init_params, **_):
    """Initialize or reinitialize empty tagit repository.

    Internally tagit repositories are the same as git repositories. Tagit only serves as another
    wrapper that manages the identifications and history using git tags.

    If ``vcs_init_params['branch_on_major']`` is ``True`` then tagit will not create new branches
    for new major versions and overall history of tags will be linear. Otherwise whenever we are
    registering new version, we create new branch for major version and new commit for minor
    version.

    :param str pcs_path: path where the perun repository was initialized
    :param str vcs_path: path, where the tagit repository will be initialized
    :param dict vcs_init_params: (key, value) dictionary of parameters for initialized tagit
        repository. This contains both parameters for tagit and for git
    :return: whether the tagit repository was successfully initialized
    """
    # Extract the branch_on_major option, and push rest to the git
    branch_on_major = vcs_init_params.get('branch_on_major', False)
    vcs_init_params.pop('branch_on_major', None)

    # Delegate initialization of wrapped to perun.vcs.git module
    vcs_init_result = perun.vcs.init('git', vcs_path=vcs_path, vcs_init_params=vcs_init_params)

    # Set branch_on_major by default to False. If we set something in vcs_init then we use the value
    pcs = PCS(pcs_path)
    config.set_key_at_config(pcs.local_config(), 'vcs.branch_on_major', branch_on_major)

    return vcs_init_result


def _get_minor_head(tagit_repo):
    """Returns the current HEAD of the the project.

    This corresponds to the tag obtained by parsing the current HEAD SHA using the ``git describe``.

    :param tagit_repo: tagit repository object (basically git repository object)
    :return str: string representation of current HEAD of the project
    """
    assert False and "Not implemented yet"
    return None


def _get_head_major_version(tagit_repo):
    """Returns the current HEAD major version of the project

    If we have specified ``local.single_versioning`` as True, then this returns the name of the
    project, otherwise returns currently "checked-out" branch.

    :param tagit_repo: tagit repository object (basically git repository object)
    :return str: representation of current head major version
    """
    return None


def _walk_minor_versions(tagit_repo, head):
    """Walks through the list of tags (minor versions) corresponding to the current major version.

    According to the current major version (current branch), this iterates through all of the tags
    that corresponds to this major version in sorted order.

    :param tagit_repo: tagit repository object (basically git repository object)
    :param head: current head, or the starting point of the major version we are iterating through
    :return MinorVersion: yielded stream of minor version objects
    """
    yield None


def _walk_major_versions(tagit_repo):
    """Walks through the list of major versions for whole project

    :param tagit_repo: tagit repository object (basically git repository object)
    :return str: yielded stream of strings representing the major versions of project
    """
    yield None


def _get_minor_version_info(tagit_repo, minor_version):
    """Returns parsed information about specified minor version

    :param tagit_repo: tagit repository object (basically git repository object)
    :param str minor_version: identification of minor version (git tag)
    :return MinorVersion: minor version version (date author email checksum desc parents)
    """
    return None


def _check_minor_version_validity(tagit_repo, minor_version):
    """Checks the validity of the minor version, whether it can be used

    :param tagit_repo: tagit repository object (basically git repository object)
    :param str minor_version: identification of minor version (git tag)
    :return: whether the specified minor_version is valid or not
    """
    return False


def _massage_parameter(tagit_repo, parameter, parameter_type=None):
    """Massages given parameter to unified representation within the repositories

    Takes a parameter (a revision), of a given parameter_type (tree, commit, blob), and uses
    rev-parse to translate this to a SHA usable by others

    :param tagit_repo: tagit repository object (basically git repository object)
    :param parameter: revision we are trying to check
    :param parameter_type: type of the parameter we are massaging (object, blob)
    :raises VersionControlSystemException: if there happens an error during the rev-parsing of the
        parameter
    :return str: massaged representation of the given parameter of parameter_type
    """
    return None