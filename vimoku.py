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

__version__ = '1.0.0'



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
REDIRECTION = 'This page has been moved [[{newname}|here]].'
TERM_WIDTH = shutil.get_terminal_size().columns


def lprint(*args, **kwargs) -> print:
    if DEBUG:  return print(*args, **kwargs)


def parse_cli() -> dict:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('pages', nargs='+', type=str, help='pages to edit')
    default_ini = os.environ.get('XDG_CONFIG_HOME', '~/.config') + '/vimoku/vimoku.ini'
    parser.add_argument('--config', '-c', type=str, help='configuration file to use', default=default_ini)
    parser.add_argument('--message', '-m', type=str, help='version message for the wiki', default=DEFAULT_MESSAGE)
    # parser.add_argument('--editor', '-e', type=str, help='the editor to use', default=None)  # TODO: require profound changes in config handling
    parser.add_argument('--minor', action='store_true', help='whether the modification is minor or not', default=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--move-to', type=str, help='Move pages toward given namespace, if they do not already exists')
    group.add_argument('--copy-to', type=str, help='Copy pages toward given namespace, if they do not already exists')
    parser.add_argument('--redirect', type=str, help='Moved pages are replaced by a link to the new page')
    parser.add_argument('--fix-backlinks', action='store_true', help='Modify (if possible) the pages linking to the moved page to link to the new page')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

    return parser.parse_args()


def read_config(configfile:str) -> (str, str, str):
    config = configparser.ConfigParser()
    config.read(os.path.expanduser(configfile))
    return config['DEFAULT']

def get_client(config:str) -> DokuWikiClient:
    """Create the DokuWikiClient instance, and patch it with more functions"""
    conf = read_config(config)
    client = DokuWikiClient(conf['url'], conf['user'], conf['password'])
    def with_additional_methods(theclient):
        def page(pagename:str, rev=None):
            "Wraps client.page to make it reject category name such as 'page:'"
            if pagename.endswith(':'):
                raise ValueError(f"You shouldn't ask for a category content with client.page() function: '{pagename}'")
            return theclient.page_real(pagename, rev)
        def has_page(pagename:str) -> bool:
            # WARNING: for dokuwiki, 'page' and 'page:' are equivalent.
            #  But in this source code, we want it to give different answers depending if 'page' is a category.
            #  if the page 'page' exists on the remote wiki, then 'page' returns True.
            #  But 'page:' will return true iif there is at least one page in the 'page' category.
            #  That could be for instance 'page:page' or 'page:page:page'.
            # WARNING: if unpatched, client.page() accepts 'page:', and will treat it as 'page'.
            if pagename.endswith(':'):
                return bool(client.pagelist(pagename[-1]))  # at least one subpage
            if pagename.endswith(':*'):
                return bool(client.pagelist(pagename[-2]))  # at least one subpage
            # We now test specifically the page, not the category.
            try:
                theclient.page_info(pagename)
            except DokuWikiXMLRPCError as err:
                if err.message == 'The requested page does not exist':
                    return False
                else:  raise
            else:
                return True
        theclient.has_page = has_page
        theclient.page, theclient.page_real = page, theclient.page
        return theclient
    return with_additional_methods(client)

def get_editor_and_options(configfile:str):
    config = read_config(configfile)
    editor_options = config['editor_options']
    editor = config['editor'] or os.environ.get('EDITOR') or DEFAULT_EDITOR
    return editor, editor_options

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
                print(f'warning: page {already_locked} was not unlocked.')
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
        # print('TMP:', tmpfile)
        max_key_len = max(map(len, simplassocs))
        for key, val in assocs.items():
            fd.write(f"{revsimplassocs[key].ljust(max_key_len)}: {val}\n")
        fd.write(f"\n\n# lines starting with a '#' will be ignored.\n# edit lines freely, but keep the colons followed by a space.\n# delete {objname} you want to {action}.")
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
        if client.has_page(page):
            content = client.page(page)
            with open(fname, 'w') as fd:
                fd.write(content)
        else:  # page does not exists
            print(f"warning: page {page} couldn't be found on remote wiki")
            content = None
            # NB: if the file doesn't exist, let the editor create it ; it will indicate the «new file» status to the user, confirming the inexistance of the file on the wiki.
        filehashes[fname] = page, hash(content)
    # edition
    run_editor(editor, editor_options, filehashes)
    # detect and send the modified files
    modified_files = {}  # filename -> page
    for fname, (page, ini_hash) in filehashes.items():
        try:
            with open(fname) as fd:  new_hash = hash(fd.read())
        except FileNotFoundError:
            pass  # it appears that user didn't want to edit that new file
        else:
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


def edit_pages(pages, message, config, client, cli_args):
    while pages:
        pages = run_main_sequence(pages, message, config, client, cli_args)


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
    editor, editor_options = get_editor_and_options(config)
    edition_dir, modified_files, all_files = edition_sequence(editor, editor_options, edition_dir, pages, client)

    # choose messages
    if modified_files:
        messages = setdict_sequence(editor, editor_options, {fname: message for fname in modified_files}, 'files', 'discard from upload')

    # upload
    if not DRY_RUN and modified_files:
        upload_work(modified_files, messages, client)
    if try_unlock(pages, client):  # TODO: improve to know exactly which files are not unlocked
        print("Couldn't unlock some pages (probably new files ?)")

    # cleanup
    new_files = tuple(map(os.path.basename, cleanup_known(edition_dir, modified_files, all_files, client)))
    if new_files:
        new_files = choice_sequence(editor, editor_options, new_files, 'files', 'discard from upload')
    print(f"Done !  ({len(modified_files) or 'no'} files uploaded, {len(new_files) or 'no'} new files)")
    return new_files


def move_page(pagename:str, newname:str, client, delete_source:bool, redirect:bool):
    if DRY_RUN:
        lprint(f"{'MV' if delete_source else 'CP'} {pagename}\t->\t{newname}")
        return
    # create the target page
    if try_lock(newname, client):
        content = client.page(pagename)
        r = client.put_page(newname, content, f'moved from {pagename}')
        if r is not None:
            raise ValueError(f"Unexpected output for upload of page {newname}: {r}")
        # delete the source if asked to
        if delete_source:
            if try_lock(pagename, client):
                content = REDIRECTION.format(newname=newname, pagename=pagename) if redirect else ''
                client.put_page(pagename, content, f'moved to {newname}')
                try_unlock(pagename, client)
            else:
                print(f"Source {pagename} couldn't be deleted (locked)")
        # unlock and quit
        if not try_unlock(newname, client):
            lprint(f"Couldn't unlock page {pagename}.")
        return True

def list_named_pages(pagenames:[str], client) -> [str]:
    """Yield all wiki pages shadowed by given (category or page) names."""
    for pagename in pagenames:
        if pagename.endswith(':*'):  # we want the content of the category of that name
            yield from (p['id'] for p in client.pagelist(pagename[:-2]))
        elif pagename.endswith(':'):  # we want the content of the category of that name
            yield from (p['id'] for p in client.pagelist(pagename[:-1]))
        else:  # we want the page of that name
            if not client.has_page(pagename):
                print(f"Page {pagename} doesn't exists on remote wiki.\nAbort.")
                exit(1)
            yield pagename



def compute_moves(pagenames:[str], target:str, client):
    """Yield pairs (pagename, new moved names), describing a move to perform.
    If a file cannot be moved, its associated value is None"""
    def is_explicit_category(name:str) -> bool:  return name.endswith(':')
    def target_is_explicit_category() -> bool:  return is_explicit_category(target)
    def basename(pagename:str) -> str:
        "Return the page name, without the categories"
        return pagename.split(':')[-1]
    def is_movable(pagename:str, category:str) -> bool:
        "true if moving pagename to category wouldn't overwrite an existing page"
        return not client.has_page(moved_name(pagename, category))
    def moved_name(pagename:str, category:str) -> str:
        "the name of the page that would result in moving given pagename to category"
        return f'{category.rstrip(":")}:{basename(pagename)}'

    if client.has_page(target):  # target is an existing page. It therefore must be understood as a category
        target += ':'

    if len(pagenames) == 1 and not pagename[0].endswith((':', ':*')):  # it's a single page
        pagename = pagenames[0]
        if client.has_page(pagename):
            if target_is_explicit_category():
                if is_movable(pagename, target):
                    yield pagename, moved_name(pagename, target)
                else:
                    print("error: Page {moved_name(pagename, target)} already exists, can't move {pagename} to {target}.")
                    yield pagename, None
            else:  # target is a non existing page
                assert not client.has_page(target)
                yield pagename, target  # direct renaming
        else:
            print('error: Page {pagename} does not exists.')
            yield None, pagename  # first item being None is equivalent to "that page doesn't exists"
    else:  # there is multiple pages to move (multiple pagenames, or one pagename that is a category)
        # target must be a category
        if not target.endswith(':'): target += ':'
        # lets handle all inputs, one argument at a time
        for pagename in pagenames:
            subpages = tuple(list_named_pages([pagename], client))
            # print('FLT:', pagename, subpages)
            if pagename.endswith(':'):  # take only the content
                subnewnames = {subpage: target + subpage[len(basename(pagename[-1])):] for subpage in subpages}
            elif pagename.endswith(':*'):  # take only the content
                subnewnames = {subpage: target + subpage[len(pagename)-1:] for subpage in subpages}
            else:  # it's a single page to move
                assert client.has_page(pagename)
                yield pagename, moved_name(pagename, target)
                continue
            for subpage, subnewname in subnewnames.items():
                yield subpage, subnewname if is_movable(subpage, subnewname) else None


def substitute_in_page(pagename, substitutions:dict, message:str, client):
    "Retrieve given page and change it using given substitutions, then upload it with given message"
    if try_lock(pagename, client) and not DRY_RUN:
        content = client.page(pagename)
        for string, sub in substitutions.items():
            content = content.replace(string, sub)
        r = client.put_page(pagename, content, message)
        if r is not None:
            raise ValueError(f"Unexpected output for upload of page {page}: {r}")
        if not try_unlock(pagename, client):
            lprint(f"Couldn't unlock page {pagename}.")
        return True

def save_list_into_tempfile(to_save:iter) -> str:
    """Save given objects as strings, one per line of a tempfile.
    The name of the tempfile will be returned."""
    with tempfile.NamedTemporaryFile('w', delete=False) as fd:
        for obj in to_save:
            fd.write(str(obj) + '\n')
        return fd.name

def move_pages(pagenames:[str], target:str, config:str, client, delete_source:bool=False, redirect:bool=False, fix_backlinks:bool=False):
    """Move given pages to given category, iif the pages exists,
    and if this wouldn't lead to any suppression."""
    # get moves, ensure all are possible
    moves = dict(compute_moves(pagenames, target, client))
    if not all(moves.values()) or not all(moves):  # any of them being None/impossible to move ?
        print('error: Abort.')
        return

    # let user edit the moves
    editor, editor_options = get_editor_and_options(config)
    moves = setdict_sequence(editor, editor_options, moves, objname='renames' if delete_source else 'copies', action='cancel')

    # make the moves, fix backlinks
    unmoved_pages, unfixed_pages = {}, {}
    for idx, (page, newname) in enumerate(moves.items(), start=1):
        print('\r' + TERM_WIDTH * ' ', end='', flush=True)
        print(f'\rmoving page {idx} of {len(moves)}…', end='', flush=False)
        if fix_backlinks:
            backlinkers = client.backlinks(page)
            for blidx, backlinker in enumerate(backlinkers, start=1):
                print(f'\rmoving page {idx} of {len(moves)}… fix {blidx}/{len(backlinkers)} backlinks…', end='', flush=True)
                if not substitute_in_page(backlinker, {'[['+page: '[['+newname, '|'+page: '|'+newname}, f"fix links to newly moved {newname}", client):
                    unfixed_pages.add(backlinker)  # one more page that couldn't be modified
            # raise NotImplementedError("fix_backlinks option is not yet implemented")
        if not move_page(page, newname, client, delete_source, redirect):
            unmoved_pages.add(page)  # one more page that couldn't be moved
    print()  # jump line

    # print info for user
    comment = ['']
    if unmoved_pages:
        comment[0] = f"Done!  ({len(unmoved_pages)} pages couldn't be moved"
        comment.append(f'the unfixed pages are saved in {save_list_into_tempfile(unfixed_pages)}')
    else:
        comment[0] = "Done!  (all pages have been moved"
    if fix_backlinks:
        if unfixed_pages:
            comment[0] += f" and {len(unfixed_pages)} pages with backlinks couldn't be fixed)"
            comment.append(f' the unfixed pages are saved in {save_list_into_tempfile(unfixed_pages)}')
        else:
            comment[0] += f" and all pages with backlinks were fixed"
    comment[0] += ")"
    for line in comment:
        print(line)

    # do all page exists ?
    # what is their basename (pagename minus categories) ?
    # do any {category}:{basename} already exists ?
    # lock them all (pagenames and movenames)
    # edit them


if __name__ == '__main__':
    args = parse_cli()
    client = get_client(args.config)

    # for p in 'cours,cours:,cours:lbienvenu,cours:lbienvenu:'.split(','):
    # for p in 'perso:testremotemove:a,perso:testremotemove:b'.split(','):
        # has = client.has_page(p)
        # content = client.page(p) if has and not p.endswith(':') else ''
        # print(p, has, len(content))
    # exit()

    if args.move_to:
        lprint('MOVE', args)
        move_pages(args.pages, args.move_to, args.config, client, delete_source=True, redirect=args.redirect, fix_backlinks=args.fix_backlinks)
    elif args.copy_to:
        lprint('COPY', args)
        move_pages(args.pages, args.move_to, args.config, client, delete_source=False, redirect=args.redirect, fix_backlinks=args.fix_backlinks)
    else:  # just do page edition
        lprint('EDIT', args)
        edit_pages(args.pages, args.message, args.config, client, args)
    if DRY_RUN:
        print('\nNB: that was a dry run')
