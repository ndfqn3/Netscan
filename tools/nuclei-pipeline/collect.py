# -*- coding: utf-8 -*-
# AllForOne-based nuclei template collector (MIT, based on AggressiveUser/AllForOne).
#
# Reads the pinned PleaseUpdateMe.txt, shallow-clones every repo (direct HTTPS),
# detects the per-repo license, extracts *.yaml/*.yml into work/pool/<repo>/ and
# writes work/collect_manifest.json. Re-running resumes: repos whose pool dir
# already exists are skipped instead of re-cloned.
#
# Env: NUCLEI_WORK (default <script dir>/work), GIT (default git), JOBS=8, CLONE_TIMEOUT=300
import json, os, re, shutil, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get('NUCLEI_WORK') or os.path.join(HERE, 'work')
LIST = os.path.join(HERE, 'PleaseUpdateMe.txt')
REPOS = os.path.join(WORK, 'repos')
POOL = os.path.join(WORK, 'pool')
MANIFEST = os.path.join(WORK, 'collect_manifest.json')
GIT = os.environ.get('GIT', 'git')
JOBS = int(os.environ.get('JOBS', '8'))
TIMEOUT = int(os.environ.get('CLONE_TIMEOUT', '300'))

LICENSE_NAMES = re.compile(r'^(license|licence|copying|copyright)(\.|$|[-_])', re.I)


def classify_license(text):
    t = text.lower()
    if "gnu affero" in t:
        return "AGPL"
    if "gnu lesser" in t:
        return "LGPL"
    if "gnu general public" in t:
        return "GPL"
    if "apache license" in t:
        return "Apache-2.0"
    if "mozilla public license" in t:
        return "MPL-2.0"
    if "redistribution and use in source and binary forms" in t:
        return "BSD"
    if "mit license" in t or "permission is hereby granted, free of charge" in t:
        return "MIT"
    if "permission to use, copy, modify, and/or distribute" in t:
        return "ISC"
    if "free and unencumbered software released into the public domain" in t:
        return "Unlicense"
    if "cc0" in t:
        return "CC0"
    return "UNKNOWN"


def detect_license(repo_dir):
    best = ("NONE", None)
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules')]
        rel = os.path.relpath(root, repo_dir)
        depth = 0 if rel == '.' else rel.count(os.sep) + 1
        if depth > 2:
            dirs[:] = []
            continue
        for fn in files:
            fp = os.path.join(root, fn)
            if not LICENSE_NAMES.match(fn):
                continue
            try:
                if os.path.getsize(fp) > 200000:
                    continue
                txt = open(fp, encoding='utf-8', errors='ignore').read(8000)
            except OSError:
                continue
            spdx = classify_license(txt)
            if spdx != "UNKNOWN":
                return spdx, os.path.relpath(fp, repo_dir)
            if best[0] == "NONE":
                best = ("UNKNOWN", os.path.relpath(fp, repo_dir))
    return best


def repo_dirname(url):
    s = url.replace('https://github.com/', '').rstrip('/')
    if s.endswith('.git'):
        s = s[:-4]
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s)


def count_yaml(d):
    n = 0
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x != '.git']
        n += sum(1 for f in files if f.endswith(('.yaml', '.yml')))
    return n


def ls_remote_head(url):
    try:
        p = subprocess.run([GIT, '-c', 'http.proxy=', '-c', 'https.proxy=', 'ls-remote', url, 'HEAD'],
                           capture_output=True, timeout=60)
        if p.returncode == 0:
            line = p.stdout.decode().strip().split()
            return line[0] if line else ''
    except Exception:
        pass
    return ''


def clone_repo(url):
    name = repo_dirname(url)
    dest = os.path.join(REPOS, name)
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    cmd = [GIT, "-c", "http.proxy=", "-c", "https.proxy=", "-c", "core.longpaths=true",
           "clone", "--depth", "1", "--single-branch", url, dest]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT)
        if p.returncode != 0:
            return {'url': url, 'dir': name, 'status': 'clone-failed',
                    'error': p.stderr.decode('utf-8', 'ignore').strip()[:300]}
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        return {'url': url, 'dir': name, 'status': 'timeout', 'error': ''}
    try:
        head = subprocess.run([GIT, "-C", dest, "rev-parse", "HEAD"],
                              capture_output=True, timeout=30).stdout.decode().strip()
    except Exception:
        head = ""
    spdx, lfile = detect_license(dest)
    n = 0
    outdir = os.path.join(POOL, name)
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in ('.git', '.github', 'node_modules')]
        for fn in files:
            if not fn.endswith(('.yaml', '.yml')):
                continue
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > 262144:
                    continue
            except OSError:
                continue
            rel = os.path.relpath(fp, dest)
            dst = os.path.join(outdir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(fp, dst)
            n += 1
    shutil.rmtree(os.path.join(dest, '.git'), ignore_errors=True)
    return {'url': url, 'dir': name, 'status': 'ok', 'head': head,
            'license': spdx, 'license_file': lfile, 'templates': n}


def process(url):
    name = repo_dirname(url)
    pool = os.path.join(POOL, name)
    if os.path.isdir(pool):
        lic, lf = ('?', None)
        rp = os.path.join(REPOS, name)
        if os.path.isdir(rp):
            lic, lf = detect_license(rp)
        return {'url': url, 'dir': name, 'status': 'ok', 'head': '',
                'license': lic, 'license_file': lf, 'templates': count_yaml(pool)}
    return clone_repo(url)


def main():
    urls = [l.strip() for l in open(LIST, encoding='utf-8') if l.strip() and not l.startswith('#')]
    os.makedirs(REPOS, exist_ok=True)
    os.makedirs(POOL, exist_ok=True)
    print('repos: %d' % len(urls), flush=True)
    results, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=JOBS) as ex:
        futs = {ex.submit(process, u): u for u in urls}
        for i, f in enumerate(as_completed(futs), 1):
            r = f.result()
            results.append(r)
            extra = ' tpl=%s lic=%s' % (r['templates'], r['license']) if r['status'] == 'ok' else ''
            print('[%3d/%d] %-58s %s%s' % (i, len(urls), r['dir'], r['status'], extra), flush=True)
    for r in results:
        if r['status'] == 'ok' and r['license'] == 'MIT' and not r['head']:
            r['head'] = ls_remote_head(r['url'])
    results.sort(key=lambda r: r['dir'])
    json.dump(results, open(MANIFEST, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    ok = [r for r in results if r['status'] == 'ok']
    mit = [r for r in ok if r['license'] == 'MIT']
    print('done in %.1fs: ok=%d mit=%d failed=%d' %
          (time.time() - t0, len(ok), len(mit), len(results) - len(ok)), flush=True)
    print('MIT repos:', ', '.join(r['dir'] for r in mit), flush=True)


if __name__ == '__main__':
    main()
