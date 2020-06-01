#!/usr/bin/python3
"""Implementation of `vimoku` command.

This command allow the user to edit dokuwiki pages easily using its $EDITOR.

It will use the XDG_CONFIG_HOME/vimoku/vimoku.ini file to get informations
such as the wiki instance to target.

Example of valid vimoku.ini:

    [default]
    url = https://wiki.example.com
    user = john
    password = qwerty

"""



import os
import time
import shlex
import shutil
import tempfile
import argparse
import subprocess
import configparser
from dokuwikixmlrpc import DokuWikiClient, DokuWikiXMLRPCError


DEFAULT_EDITOR = 'vi'  # used if CLI, configfile and $EDITOR are empty.
DEFAULT_MESSAGE = 'undocumented remote modification'
DEBUG = False  # set to true to get many lines of logging
DRY_RUN = False  # set to true to prevent any page modification


def lprint(*args, **kwargs) -> print:
    if DEBUG:  return print(*args, **kwargs)


def read_config(configfile:str) -> (str, str, str):
    config = configparser.ConfigParser()
    config.read(os.path.expanduser(configfile))
    return config['DEFAULT']

def parse_cli() -> dict:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pages', nargs='+', type=str, help='pages to edit')
    default_ini = os.environ.get('XDG_CONFIG_HOME', '~/.config') + '/vimoku/vimoku.ini'
    parser.add_argument('--config', '-c', type=str, help='configuration file to use', default=default_ini)
    parser.add_argument('--message', '-m', type=str, help='version message for the wiki', default=DEFAULT_MESSAGE)
    parser.add_argument('--editor', '-e', type=str, help='the editor to use', default=None)
    parser.add_argument('--minor', action='store_true', help='whether the modification is minor or not', default=False)
    return parser.parse_args()

def get_client(config:str) -> DokuWikiClient:
    conf = read_config(config)
    return DokuWikiClient(conf['url'], conf['user'], conf['password'])

def try_lock(pagenames, client):
    if isinstance(pagenames, str): pagenames = [pagenames]
    r = client.set_locks({'lock': pagenames})
    if all(page in r['locked'] for page in pagenames): return True
    else:
        assert any(page in r['lockfail'] for page in pagenames), r
        return False

def try_unlock(pagenames, client):
    if isinstance(pagenames, str): pagenames = [pagenames]
    r = client.set_locks({'unlock': pagenames})
    if all(page in r['unlocked'] for page in pagenames): return True
    else:
        assert any(page in r['unlockfail'] for page in pagenames)
        return False

def set_all_locks(pagenames, client) -> bool:
    """Try to set locks on all given pages ; return True on success"""
    already_locked = []
    for page in pagenames:
        if try_lock(page, client):
            already_locked.append(page)
        else:  # this one wasn't lockable: abort operation
            if try_unlock(already_locked, client):
                print(f'warning: page {locked} was not unlocked.')
            return [page for page in pagenames if page not in already_locked]
    else:  # everything ran smoothly, i.e. all pages are locked
        return []


def create_unique_dir(config) -> str:
    edition_dir = os.path.dirname(config) + f'/edition_{int(time.time())}'
    if os.path.exists(edition_dir):
        print(f"Edition directory {edition_dir} already exists. I don't know how to deal with that.\nAbort.")
        return
    else:
        lprint(f"Edition directory created as {edition_dir}")
    os.mkdir(edition_dir)
    return edition_dir

def run_editor(editor, editor_options, filenames):
    """Run editor properly. Finishes when user finishes."""
    comdir = os.path.commonpath(tuple(filenames))
    if os.path.isfile(comdir):
        comdir = os.path.dirname(comdir)
    options = shlex.split(editor_options.format(cwd=comdir))
    command = [editor, *options, *filenames]
    lprint('Invoking editor with:', command)
    p = subprocess.Popen(command)
    p.wait()


def setdict_sequence(editor, editor_options, assocs:dict, objname='lines', action='remove from choices'):
    """Provide user with a list of lines. Return those that weren't deleted"""
    # get the best key representation
    def simplified_key(key:str) -> str:
        if len(set(map(os.path.dirname, assocs.keys()))) == 1:  # only one common prefix
            return os.path.basename(key.strip())
        return key.strip()  # different prefix -> some names could be equal
    simplassocs = {simplified_key(key): key for key in assocs}
    revsimplassocs = {v: k for k, v in simplassocs.items()}
    # create the file to edit
    with tempfile.NamedTemporaryFile('w', delete=False) as fd:
        tmpfile = fd.name
        print('TMP:', tmpfile)
        max_key_len = max(map(len, simplassocs))
        for key, val in assocs.items():
            fd.write(f"{revsimplassocs[key].rjust(max_key_len)}: {val}")
        fd.write(f"\n\n# lines starting with a '#' will be ignored.\n# edit lines freely, but keep the colons.\n# delete {objname} you want to {action}.")
    # run the editor, retrieve the user's choice
    run_editor(editor, editor_options, [tmpfile])
    assocs = {}
    with open(tmpfile) as fd:
        for line in fd:
            if line.startswith('#') or ': ' not in line: continue
            key, val = line.split(': ', 1)
            assocs[simplassocs[key.strip()]] = val.strip()
    os.unlink(tmpfile)
    return assocs


def choice_sequence(editor, editor_options, choices, objname='lines', action='remove from choices'):
    """Provide user with a list of lines. Return those that weren't deleted"""
    # create the file to edit, and run the editor
    with tempfile.NamedTemporaryFile('w', delete=False) as fd:
        tmpfile = fd.name
        fd.write('\n'.join(map(str, choices)) + '\n\n' + f"# lines starting with a '#' will be ignored.\n# delete {objname} you want to {action}.")
    run_editor(editor, editor_options, [tmpfile])
    # get the user's choices
    kept = []
    with open(tmpfile) as fd:
        for line in fd:
            if line.startswith('#'): continue
            for choice in choices:
                if line.strip() == str(choice).strip():
                    kept.append(choice)
    os.unlink(tmpfile)
    return kept


def edition_sequence(editor, editor_options, edition_dir, pagenames, client):
    # retrieve each page, put it in the edition directory
    client = client or get_client(config)
    filehashes = {}  # filename -> (page, hash)   (to later determine if a modification was made)
    for page in pagenames:
        fname = edition_dir + '/' + page
        try:
            content = client.page(page)
        except DokuWikiXMLRPCError as err:
            content = None
            print(f"warning: page {page} couldn't be found on remote wiki")
            if err.message != 'The requested file does not exist':
                raise  # i don't know what the problem is
        else:
            with open(fname, 'w') as fd:
                fd.write(content)
            # NB: if the file doesn't exist, let the editor create it ; it will indicate the «new file» status to the user, confirming the inexistance of the file on the wiki.
        filehashes[fname] = page, hash(content)
    # edition
    run_editor(editor, editor_options, filehashes)
    # detect and send the modified files
    modified_files = {}  # filename -> page
    for fname, (page, ini_hash) in filehashes.items():
        with open(fname) as fd:  new_hash = hash(fd.read())
        if new_hash != ini_hash:
            modified_files[fname] = page
    return edition_dir, modified_files, set(filehashes.keys())


def upload_work(modified_files, messages:dict, client):
    """Upload the given modified pages on the wiki"""
    for fname, page in modified_files.items():
        with open(fname) as fd: new_content = fd.read()
        message = messages[fname]
        r = client.put_page(page, new_content, message or DEFAULT_MESSAGE)
        if r is not None:
            raise ValueError(f"Unexpected output for upload of page {page}: {r}")


def cleanup_known(edition_dir, modified_files, known_files, client):
    """Remove the uploaded pages in edition directory, and the directory if possible"""
    # detect unknown files
    unkwnow_files = {}  # fname -> page
    for entry in os.scandir(edition_dir):
        path = os.path.join(edition_dir, entry.name)
        if path in known_files:  os.unlink(path)
        elif entry.is_file:  unkwnow_files[path] = entry.name
    if not unkwnow_files:  # clean everything if possible
        shutil.rmtree(edition_dir)
        lprint('Edition directory deleted.')
    return unkwnow_files


def run_main_sequence(pages, message, config, client, cli_args):
    """Lock, retrieve, let user edit, upload and cleanup, the asked wiki pages.
    Return new pages that user may want to upload."""
    failed = set_all_locks(pages, client)
    if failed:
        print(f"{len(failed)} pages were not locked: " + ', '.join(failed))
        print("Abort.")
    else:
        lprint('locks set.')

    # Create the directory that will contain the page to edit
    edition_dir = create_unique_dir(config)
    if edition_dir is None:
        print("Couldn't create a temporary directory.\nAbort.")
        exit()

    # let's edit the pages
    editor_options = read_config(config)['editor_options']
    editor = cli_args.editor or read_config(config)['editor'] or os.environ.get('EDITOR') or DEFAULT_EDITOR
    edition_dir, modified_files, all_files = edition_sequence(editor, editor_options, edition_dir, pages, client)

    # choose messages
    if modified_files:
        messages = setdict_sequence(editor, editor_options, {fname: message for fname in modified_files}, 'files', 'discard from upload')

    # upload
    if not DRY_RUN: upload_work(modified_files, messages, client)
    if try_unlock(pages, client):  # TODO: improve to know exactly which files are not unlocked
        print("Couldn't unlock some pages (probably new files ?)")

    # cleanup
    new_files = tuple(map(os.path.basename, cleanup_known(edition_dir, modified_files, all_files, client)))
    if new_files:
        new_files = choice_sequence(editor, editor_options, new_files, 'files', 'discard from upload')
    print(f"Done !  ({len(modified_files) or 'no'} files uploaded, {len(new_files) or 'no'} new files)")
    return new_files


if __name__ == '__main__':
    args = parse_cli()
    pages = args.pages
    client = get_client(args.config)

    while pages:
        pages = run_main_sequence(pages, args.message, args.config, client, args)
