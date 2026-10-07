# -*- coding: utf-8 -*-
# Generate internal/poc/nuclei_pocs_gen.go from work/selected.jsonl (multi-request/raw schema).
#
# Env: NUCLEI_WORK (default <script dir>/work)
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get('NUCLEI_WORK') or os.path.join(HERE, 'work')
SELECTED = os.path.join(WORK, 'selected.jsonl')
EXTRA = os.environ.get('EMIT_EXTRA') == '1'
if EXTRA:
    OUT = os.path.normpath(os.path.join(HERE, '..', '..', 'internal', 'poc', 'nuclei_pocs_extra_gen.go'))
else:
    OUT = os.path.normpath(os.path.join(HERE, '..', '..', 'internal', 'poc', 'nuclei_pocs_gen.go'))
OFFICIAL = 'projectdiscovery/nuclei-templates'


def gq(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append('\\x%02x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def go_strs(lst):
    return "[]string{" + ", ".join(gq(x) for x in lst) + "}"


def emit_matcher(m):
    parts = ['Type: ' + gq(m['type'])]
    if m.get('part') and m['part'] != 'body' and m['type'] != 'status':
        parts.append('Part: ' + gq(m['part']))
    if m['type'] == 'status':
        parts.append('Status: []int{' + ', '.join(str(x) for x in m['status']) + '}')
    if m['type'] in ('word', 'oast_request'):
        parts.append('Words: ' + go_strs(m.get('words', [])))
        if m.get('ci'):
            parts.append('CaseInsensitive: true')
    if m['type'] in ('regex', 'oast_request'):
        if m.get('regex'):
            parts.append('Regex: ' + go_strs(m['regex']))
    if m['type'] == 'size':
        parts.append('Size: []int{' + ', '.join(str(x) for x in m['size']) + '}')
    if m['type'] == 'dsl':
        parts.append('DSL: ' + go_strs(m['dsl']))
        if m.get('cond') == 'and':
            parts.append('Condition: "and"')
    if m['type'] == 'oast':
        parts = ['Type: "oast"', 'Words: ' + go_strs(m.get('words', []))]
    if m.get('negative'):
        parts.append('Negative: true')
    return 'POCMatcher{' + ', '.join(parts) + '}'


def emit_request(rq):
    proto = (rq.get('proto') or 'http').lower()
    if proto in ('tcp', 'udp'):
        parts = ['Proto: ' + gq(proto), 'Payload: ' + gq(rq.get('payload', ''))]
        if rq.get('payloads'):
            ps = ", ".join(
                'POCPayload{Name: %s, Values: %s}' % (gq(p['name']), go_strs([str(v) for v in p['values']]))
                for p in rq['payloads'])
            parts.append('Payloads: []POCPayload{' + ps + '}')
        if rq.get('attack'):
            parts.append('Attack: ' + gq(rq['attack']))
        return 'POCRequest{' + ', '.join(parts) + '}'
    parts = []
    if rq.get('raw'):
        parts = ['Raw: ' + gq(rq['raw'])]
    else:
        parts = ['Method: ' + gq(rq.get('method') or 'GET'), 'Path: ' + gq(rq['path'])]
        if rq.get('headers'):
            hs = ", ".join('%s: %s' % (gq(k), gq(v)) for k, v in rq['headers'].items())
            parts.append('Headers: map[string]string{' + hs + '}')
        if rq.get('body'):
            parts.append('Body: ' + gq(rq['body']))
    if rq.get('redirects'):
        parts.append('Redirects: true')
    if rq.get('payloads'):
        ps = ", ".join(
            'POCPayload{Name: %s, Values: %s}' % (gq(p['name']), go_strs([str(v) for v in p['values']]))
            for p in rq['payloads'])
        parts.append('Payloads: []POCPayload{' + ps + '}')
    if rq.get('attack'):
        parts.append('Attack: ' + gq(rq['attack']))
    return 'POCRequest{' + ', '.join(parts) + '}'


def main():
    raw = open(SELECTED, encoding='utf-8').read().strip()
    if raw.startswith('['):
        recs = json.loads(raw)
    else:
        recs = [json.loads(l) for l in raw.splitlines() if l.strip()]
    lines, seen, cur = [], set(), None
    n_off = n_new = 0
    for r in recs:
        rid = '-'.join((r['id'] or 'poc').strip().split()) or 'poc'
        if rid in seen:
            continue
        seen.add(rid)
        if r['src'] != cur:
            cur = r['src']
            lines.append('\t// source: %s (MIT)' % cur)
        if r['src'] == OFFICIAL:
            n_off += 1
        else:
            n_new += 1
        reqs = 'Requests: []POCRequest{' + ', '.join(emit_request(rq) for rq in r['requests']) + '}'
        if r.get('oast'):
            reqs += ', OAST: true'
        vpart = ''
        if r.get('variables'):
            vpart = ', Variables: map[string]string{' + ', '.join(
                '%s: %s' % (gq(k), gq(v)) for k, v in r['variables'].items()) + '}'
        epart = ''
        if r.get('extractors'):
            es = []
            for ex in r['extractors']:
                ps = ['Type: ' + gq(ex['type'])]
                if ex.get('name'):
                    ps.append('Name: ' + gq(ex['name']))
                if ex.get('internal'):
                    ps.append('Internal: true')
                if ex.get('part'):
                    ps.append('Part: ' + gq(ex['part']))
                if ex.get('regex'):
                    ps.append('Regex: ' + go_strs(ex['regex']))
                if ex.get('group'):
                    ps.append('Group: %d' % ex['group'])
                if ex.get('json'):
                    ps.append('JSON: ' + go_strs(ex['json']))
                if ex.get('kval'):
                    ps.append('KVal: ' + go_strs(ex['kval']))
                es.append('POCExtractor{' + ', '.join(ps) + '}')
            epart = ', Extractors: []POCExtractor{' + ', '.join(es) + '}'
        resp = 'MatchersCondition: %s, Matchers: []POCMatcher{%s}' % (
            gq(r['mcond']), ', '.join(emit_matcher(m) for m in r['matchers']))
        lines.append('\t{ID: %s, Name: %s, Severity: %s%s%s, %s, Response: POCResponse{%s}},'
                     % (gq(rid), gq(r['name']), gq(r['sev']), vpart, epart, reqs, resp))
    varname = 'nucleiExtraPOCs' if EXTRA else 'nucleiPOCs'
    header = '''package poc

// Code generated by tools/nuclei-pipeline/emit.py from nuclei templates. DO NOT EDIT.
// Sources (MIT-licensed only):
//   - projectdiscovery/nuclei-templates (Copyright (c) ProjectDiscovery, Inc., MIT)
//   - AllForOne pool (github.com/AggressiveUser/AllForOne, MIT) MIT-licensed repos, see THIRD_PARTY_NOTICES.md
// 共 %d 条: 支持多请求/raw/payloads/变量/helper/索引DSL + status/word/regex/size/dsl 子集 (HTTP 模板)
var %s = []POCTemplate{
''' % (n_off + n_new, varname)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(header)
        f.write('\n'.join(lines))
        f.write('\n}\n')
    print('generated %d templates (%d official + %d allforone-mit) -> %s (%.1f MB)'
          % (n_off + n_new, n_off, n_new, OUT, os.path.getsize(OUT) / 1048576.0))


if __name__ == '__main__':
    main()
