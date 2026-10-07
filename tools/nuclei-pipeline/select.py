# -*- coding: utf-8 -*-
# Select the final POC set (work/selected.jsonl) from work/converted.jsonl.
#
# Policy: MIT-licensed sources only (projectdiscovery/nuclei-templates + AllForOne
# pool repos whose LICENSE classifies as MIT). Dedupe case-insensitively by
# template id (official wins). Quality gates: malformed paths, weak OR matchers,
# weak PHP-generic words in pool templates, tested-FP denylist.
#
# Env: NUCLEI_WORK (default <script dir>/work)
import collections, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get('NUCLEI_WORK') or os.path.join(HERE, 'work')
MANIFEST = os.path.join(WORK, 'collect_manifest.json')
CONVERTED = os.path.join(WORK, 'converted.jsonl')
OUT = os.path.join(WORK, 'selected.jsonl')
OFFICIAL = 'projectdiscovery/nuclei-templates'
WS = re.compile(r'[\s\x00-\x1f]')
# 低质模板黑名单(实测误报): CVE-2017-7529(PedroF 弱化版)仅以
# 响应头 "Content-Range"/"Server: nginx"(任一) + 206 匹配, 会把任何支持
# Range 的服务器(Apache 等)判为 Nginx 整数溢出。
DENY_IDS = {'cve-2017-7529', 'apache-ambari-weakpass', 'cve-2020-17453.yaml',
            'thinkcmf-arbitary', 'thinkcmf-arbitrary-code-execution', 'thinkcmf-rce',
            'cve-2023-37265', 'sql'}
# 池模板里仅靠 PHP 通用字样(PHP Version/PHP Extension/phpinfo)的 OR 匹配过弱, 排除
PHP_WEAK = {'php version', 'php extension', 'phpinfo'}


def req_paths(r):
    out = []
    for rq in r['requests']:
        if rq.get('raw'):
            first = rq['raw'].splitlines()[0] if rq['raw'].strip() else ''
            parts = first.split()
            out.append(parts[1] if len(parts) >= 2 else '')
        else:
            out.append(rq.get('path', ''))
    return out


def reject(r):
    if r['src'] != OFFICIAL and r['id'].lower() in DENY_IDS:
        return 'denylist'
    if any(WS.search(p) for p in req_paths(r)):
        return 'bad-path'
    if r['mcond'].lower() != 'and' and len(r['matchers']) > 20:
        return 'weak-or'
    if r['src'] != OFFICIAL:
        for m in r['matchers']:
            if m['type'] == 'word':
                for w in m['words']:
                    if w.strip().lower() in PHP_WEAK:
                        return 'weak-word'
    return None


def main():
    lic = {r['dir']: r.get('license') for r in json.load(open(MANIFEST, encoding='utf-8'))}
    mit = {k for k, v in lic.items() if v == 'MIT'}
    recs = [json.loads(l) for l in open(CONVERTED, encoding='utf-8')]
    off = [r for r in recs if r['src'] == OFFICIAL]
    pool = [r for r in recs if r['src'] != OFFICIAL and r['src'].replace('allforone/', '') in mit]
    pool.sort(key=lambda r: (r['src'], r['path']))
    seen, selected, new, dropped = set(), [], [], {}
    for r in off + pool:
        why = reject(r)
        if why:
            dropped[why] = dropped.get(why, 0) + 1
            continue
        k = r['id'].lower()
        if k in seen:
            continue
        if r['src'] != OFFICIAL and all(m['type'] == 'status' for m in r['matchers']):
            continue
        seen.add(k)
        selected.append(r)
        if r['src'] != OFFICIAL:
            new.append(r)
    json.dump(selected, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False)
    n_off = len(selected) - len(new)
    print('selected templates: %d (official %d + new MIT %d)' % (len(selected), n_off, len(new)))
    print('quality-dropped:', dropped)
    print('new by src:', collections.Counter(r['src'].replace('allforone/', '') for r in new).most_common())


if __name__ == '__main__':
    main()
