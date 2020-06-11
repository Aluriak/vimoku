#!/usr/bin/python3
"""Implementation of `vimoku` command.

This command allow the user to edit dokuwiki pages easily using its $EDITOR.

It will use the XDG_CONFIG_HOME/vimoku/vimoku.ini file to get informations
such as the wiki instance to target.

Example of valid vimoku.ini:

    [wiki:default]
    url = https://wiki.example.com
    user = john
    password = qwerty

"""

__version__ = '1.0.2'



import os
import time
import shlex
import shutil
import tempfile
import argparse
import subprocess
import configparser
from collections import defaultdict
from dokuwikixmlrpc import DokuWikiClient, DokuWikiXMLRPCError


DEFAULT_EDITOR = 'vi'  # used if CLI, configfile and $EDITOR are empty.
DEFAULT_MESSAGE = 'undocumented remote modification'
DEBUG = True  # set to true to get many lines of logging
DRY_RUN = False  # set to true to prevent any page modification
REDIRECTION = 'This page has been moved [[{newname}|here]].'
TERM_WIDTH = shutil.get_terminal_size().columns
INI_SECTION_OPTIONS = 'options'
INI_WIKI_MARKER = 'wiki:'  # prefix that indicates that a INI section describes a wiki
WIKI_SEP = ':::'  # the token separating wiki and page name in the file names
INPUT_WIKI_SEP = '/'  # another wiki seperator accepted in CLI


def sanitize_input_pagename(name:str):
    if INPUT_WIKI_SEP in name:
        assert name.count(INPUT_WIKI_SEP) == 1
        name = name.replace(INPUT_WIKI_SEP, WIKI_SEP, 1)
    return name

def fullpagename_from_wiki_page(wiki:str, pagename:str) -> str:
    assert WIKI_SEP not in pagename
    return wiki + WIKI_SEP + pagename

def wiki_page_from_fullpagename(fullpagename:str, default:str) -> (str, str):
    if WIKI_SEP in fullpagename:
        assert fullpagename.count(WIKI_SEP) == 1
        return fullpagename.split(WIKI_SEP)
    else:  # no wiki given, use the default
        return default, fullpagename

def client_page_from_fullpagename(fullpagename:str, clients) -> (DokuWikiClient, str):
    if isinstance(clients, DokuWikiClient):  # clients was already chosen for this page
        _, p = wiki_page_from_fullpagename(fullpagename, default=None)
        return clients, p  # we can only hope that choice was wise
    else:  # we got a real ClientBatch instance
        w, p = wiki_page_from_fullpagename(fullpagename, default=clients.default_name)
        return clients[w], p

def wikiname_from_fullname(fullpagename:str, default:str):
    return wiki_page_from_fullpagename(fullpagename, default)[0]


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
    return config


def pages_by_client(pagenames:[str], clients) -> {DokuWikiClient: [str]}:
    """Return the map between each client and the pagenames in the wiki they are describing"""
    assoc = defaultdict(list)
    for pagename in pagenames:
        client, page = client_page_from_fullpagename(pagename, clients)
        assoc[client].append(page)
    return dict(assoc)


class ClientBatch():
    """A proxy to access DokuWikiClient instances based on their name.
    Only create the DokuWikiClient instance when asked (that feature
    is the reason why we enclose that in a dedicated object)"""
    def __init__(self, configfile:str):
        self.config = configparser.ConfigParser()
        self.config.read(os.path.expanduser(configfile))
        self.clients = {}  # name -> DokuWikiClient
        lprint('detected wikis:', ', '.join(self.sections()))
    @property
    def default_name(self) -> str:
        return self.config['options'].get('default_wiki', 'wiki:default')
    def default(self) -> DokuWikiClient:
        return self[self.default_name]
    def sections(self):
        return set(s[len(INI_WIKI_MARKER):] for s in self.config.sections() if s.startswith(INI_WIKI_MARKER))
    def __getitem__(self, name) -> DokuWikiClient:
        sections = self.sections()
        if name in sections:
            if name not in self.clients:  # not yet created, let's initialize it
                self.clients[name] = get_client_from_parsed_config(self.config[INI_WIKI_MARKER + name])
            return self.clients[name]
        raise KeyError(f"Configuration file doesn't define a wiki named '{name}'. Candidates: " + ', '.join(sections))

def get_clients(configfile:str) -> ClientBatch:
    return ClientBatch(configfile)

def get_client_from_parsed_config(config:configparser.ConfigParser) -> DokuWikiClient:
    """Create the DokuWikiClient instance, and patch it with more functions"""
    client = DokuWikiClient(config['url'], config['user'], config['password'])
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
    editor_options = config['options']['editor_options']
    editor = config['options']['editor'] or os.environ.get('EDITOR') or DEFAULT_EDITOR
    return editor, editor_options

def try_lock(allpagenames, clients):
    if isinstance(allpagenames, str): allpagenames = [allpagenames]
    for client, pagenames in pages_by_client(allpagenames, clients).items():
        r = client.set_locks({'lock': pagenames})
        if all(page in r['locked'] for page in pagenames):
            continue
        else:
            assert any(page in r['lockfail'] for page in pagenames), r
            return False
    return True

def try_unlock(allpagenames, client):
    if isinstance(allpagenames, str): allpagenames = [allpagenames]
    for client, pagenames in pages_by_client(allpagenames, clients).items():
        r = client.set_locks({'unlock': pagenames})
        if all(page in r['unlocked'] for page in pagenames):
            continue
        else:
            assert any(page in r['unlockfail'] for page in pagenames)
            return False
    return True

def set_all_locks(pagenames, clients) -> bool:
    """Try to set locks on all given pages ; return True on success"""
    already_locked = []
    for page in pagenames:
        if try_lock(page, clients):
            already_locked.append(page)
        else:  # this one wasn't lockable: abort operation
            if try_unlock(already_locked, clients):
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
    # print('FILES TO EDIT:', ', '.join(filenames))
    comdir = os.path.commonpath(tuple(filenames))
    if not os.path.isdir(comdir):  # isfile would return False if there is only 1 filename, that is a new file not yet created on the system
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


def edition_sequence(editor, editor_options, edition_dir, fullpagenames, clients):
    # retrieve each page, put it in the edition directory
    filehashes = {}  # filename -> (page, hash)   (to later determine if a modification was made)
    for fullpagename in fullpagenames:
        client, pagename = client_page_from_fullpagename(fullpagename, clients)
        fname = edition_dir + '/' + fullpagename
        if client.has_page(pagename):
            content = client.page(pagename)
            with open(fname, 'w') as fd:
                fd.write(content)
        else:  # page does not exists
            print(f"warning: page {pagename} couldn't be found on remote wiki '{wikiname_from_fullname(fullpagename, clients.default_name)}'")
            content = None
            # NB: if the file doesn't exist, let the editor create it ; it will indicate the «new file» status to the user, confirming the inexistance of the file on the wiki.
        filehashes[fname] = fullpagename, hash(content)
    # edition
    run_editor(editor, editor_options, filehashes)
    # detect and send the modified files
    modified_files = {}  # filename -> page
    for fname, (fullpagename, ini_hash) in filehashes.items():
        try:
            with open(fname) as fd:  new_hash = hash(fd.read())
        except FileNotFoundError:
            pass  # it appears that user didn't want to edit that new file
        else:
            if new_hash != ini_hash:
                modified_files[fname] = fullpagename
    return edition_dir, modified_files, set(filehashes.keys())


def upload_work(modified_files, messages:dict, clients):
    """Upload the given modified pages on the wiki"""
    for fname, fullpage in modified_files.items():
        with open(fname) as fd: new_content = fd.read()
        message = messages[fname]
        client, page = client_page_from_fullpagename(fullpage, clients)
        r = client.put_page(page, new_content, message or DEFAULT_MESSAGE)
        if r is not None:
            raise ValueError(f"Unexpected output for upload of page {fullpage}: {r}")


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


def edit_pages(pages, message, config, clients, cli_args):
    while pages:
        pages = run_main_sequence(pages, message, config, clients, cli_args)


def run_main_sequence(pages, message, config, clients, cli_args):
    """Lock, retrieve, let user edit, upload and cleanup, the asked wiki pages.
    Return new pages that user may want to upload."""
    failed = set_all_locks(pages, clients)
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
    edition_dir, modified_files, all_files = edition_sequence(editor, editor_options, edition_dir, pages, clients)

    # choose messages
    if modified_files:
        messages = setdict_sequence(editor, editor_options, {fname: message for fname in modified_files}, 'files', 'discard from upload')

    # upload
    if not DRY_RUN and modified_files:
        upload_work(modified_files, messages, clients)
    if try_unlock(pages, clients):  # TODO: improve to know exactly which files are not unlocked
        print("Couldn't unlock some pages (probably new files ?)")

    # cleanup
    new_files = tuple(map(os.path.basename, cleanup_known(edition_dir, modified_files, all_files, clients)))
    if new_files:
        new_files = choice_sequence(editor, editor_options, new_files, 'files', 'discard from upload')
    print(f"Done !  ({len(modified_files) or 'no'} files uploaded, {len(new_files) or 'no'} new files)")
    return new_files


def move_page(fullpagename:str, newfullname:str, clients, delete_source:bool, redirect:bool):
    if DRY_RUN:
        lprint(f"{'MV' if delete_source else 'CP'} {fullpagename}\t->\t{newfullname}")
        return True  # mock the move
    # create the target page
    client_src, pagename = client_page_from_fullpagename(fullpagename, clients)
    client_trg, newname = client_page_from_fullpagename(newfullname, clients)
    if try_lock(newname, client_trg):
        content = client_src.page(pagename)
        r = client_trg.put_page(newname, content, f'moved from {fullpagename}')
        if r is not None:
            raise ValueError(f"Unexpected output for upload of page {newfullname}: {r}")
        # delete the source if asked to
        if delete_source:
            if try_lock(pagename, client_src):
                content = REDIRECTION.format(newname=newfullname, pagename=fullpagename) if redirect else ''
                client_src.put_page(pagename, content, f'moved to {newfullname}')
                try_unlock(pagename, client_src)
            else:
                print(f"Source {pagename} couldn't be deleted (locked)")
        # unlock and quit
        if not try_unlock(newname, client_trg):
            lprint(f"Couldn't unlock page {newfullname}.")
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



def compute_moves(fullpagenames:[str], fulltarget:str, clients):
    """Yield pairs (pagename, new moved names), describing a move to perform.
    If a file cannot be moved, its associated value is None"""
    def is_explicit_category(name:str) -> bool:  return name.endswith(':')
    def target_is_explicit_category() -> bool:  return is_explicit_category(target)
    def basename(pagename:str) -> str:
        "Return the page name, without the categories"
        return pagename.split(':')[-1]
    def moved_name(pagename:str, category:str) -> str:
        "the name of the page that would result in moving given pagename to category"
        return f'{category.rstrip(":")}:{basename(pagename)}'
    def is_movable(pagename:str, category:str) -> bool:
        "true if moving pagename to category wouldn't overwrite an existing page"
        return not client_trg.has_page(moved_name(pagename, category))

    client_trg, target = client_page_from_fullpagename(fulltarget, clients)
    if client_trg.has_page(target) and not target.endswith(':'):  # target is an existing page. It therefore must be understood as a category
        target += ':'
    target_wiki = wikiname_from_fullname(fulltarget, clients.default_name)

    if len(fullpagenames) == 1 and not fullpagenames[0].endswith((':', ':*')):  # it's a single page
        fullpagename = fullpagenames[0]
        client_src, pagename = client_page_from_fullpagename(fullpagename, clients)
        if client_src.has_page(pagename):
            if target_is_explicit_category():
                if is_movable(pagename, target):
                    yield fullpagename, fullpagename_from_wiki_page(target_wiki, moved_name(pagename, target))
                else:
                    print("error: Page {moved_name(pagename, target)} already exists, can't move {pagename} to {target}.")
                    yield fullpagename, None
            else:  # target is a non existing page
                if client_trg.has_page(target):
                    raise ValueError("Wiki {target_wiki} already has a page {target}.")
                yield fullpagename, target  # direct renaming
        else:
            print(f'error: Page {fullpagename} does not exists.')
            yield None, pagename  # first item being None is equivalent to "that page doesn't exists"
    else:  # there is multiple pages to move (multiple pagenames, or one pagename that is a category)
        # target must be a category (because it can't be a file)
        if not target.endswith(':'): target += ':'
        # lets handle all inputs, one argument at a time
        for fullpagename in fullpagenames:
            source_wiki = wikiname_from_fullname(fullpagename, clients.default_name)
            client_src, pagename = client_page_from_fullpagename(fullpagename, clients)
            subpages = tuple(list_named_pages([pagename], client_src))
            # print('FLT:', fullpagename, pagename, subpages)
            if pagename.endswith(':'):  # take only the content
                subnewnames = {subpage: target + subpage[len(basename(pagename[-1])):] for subpage in subpages}
            elif pagename.endswith(':*'):  # take only the content
                subnewnames = {subpage: target + subpage[len(pagename)-1:] for subpage in subpages}
            else:  # it's a single page to move
                assert client_src.has_page(pagename)
                yield fullpagename, fullpagename_from_wiki_page(target_wiki, moved_name(pagename, target))
                continue
            for subpage, subnewname in subnewnames.items():
                fullsubnewname = fullpagename_from_wiki_page(target_wiki, subnewname)
                yield fullpagename_from_wiki_page(source_wiki, subpage), fullsubnewname if is_movable(subpage, subnewname) else None


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

def move_pages(pagenames:[str], target:str, config:str, clients, delete_source:bool=False, redirect:bool=False, fix_backlinks:bool=False):
    """Move given pages to given category, iif the pages exists,
    and if this wouldn't lead to any suppression."""
    # get moves, ensure all are possible
    moves = dict(compute_moves(pagenames, target, clients))
    if not all(moves.values()) or not all(moves):  # any of them being None/impossible to move ?
        print('error: Abort.')
        return

    # let user edit the moves
    editor, editor_options = get_editor_and_options(config)
    moves = setdict_sequence(editor, editor_options, moves, objname='renames' if delete_source else 'copies', action='cancel')

    # make the moves, fix backlinks
    unmoved_pages, unfixed_pages = set(), set()
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
        if not move_page(page, newname, clients, delete_source, redirect):
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


if __name__ == '__main__':
    args = parse_cli()
    # client = get_client(args.config)
    clients = get_clients(args.config)
    pages = tuple(map(sanitize_input_pagename, args.pages))

    # for p in 'cours,cours:,cours:lbienvenu,cours:lbienvenu:'.split(','):
    # for p in 'perso:testremotemove:a,perso:testremotemove:b'.split(','):
        # has = client.has_page(p)
        # content = client.page(p) if has and not p.endswith(':') else ''
        # print(p, has, len(content))
    # print(clients)
    # exit()

    if args.move_to:
        lprint('MOVE', args)
        move_pages(pages, sanitize_input_pagename(args.move_to), args.config, clients, delete_source=True, redirect=args.redirect, fix_backlinks=args.fix_backlinks)
    elif args.copy_to:
        lprint('COPY', args)
        move_pages(pages, sanitize_input_pagename(args.move_to), args.config, clients, delete_source=False, redirect=args.redirect, fix_backlinks=args.fix_backlinks)
    else:  # just do page edition
        lprint('EDIT', args)
        edit_pages(pages, args.message, args.config, clients, args)
    if DRY_RUN:
        print('\nNB: that was a dry run')
