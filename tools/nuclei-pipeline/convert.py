# -*- coding: utf-8 -*-
# Convert the collected nuclei templates (work/pool) into work/converted.jsonl.
#
# v2: supports multi http blocks, raw requests, template variables (static),
# redirects flag. Only templates our Go engine can execute are kept:
# up to 3 http blocks / 6 requests, status/word/regex/size/dsl-subset matchers,
# runtime placeholders limited to: BaseURL/RootURL/Hostname/Host/Port/Scheme/
# randstr/target/port/callback_host/callback_port + interactsh-url (HTTP OAST).
#
# Env: NUCLEI_WORK (default <script dir>/work)
import json, os, re
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get('NUCLEI_WORK') or os.path.join(HERE, 'work')
POOL = os.path.join(WORK, 'pool')
OUT = os.path.join(WORK, 'converted.jsonl')
OFFICIAL_DIR = 'projectdiscovery_nuclei-templates'
OFFICIAL_SRC = 'projectdiscovery/nuclei-templates'

import yaml

# ---------- DSL subset validation (must match the Go evaluator) ----------
ATOM_RES = [
    re.compile(r'^status_code(?:_\d+)?\s*(==|!=|>=|<=|>|<)\s*\d+$', re.I),
    re.compile(r'^duration(?:_\d+)?\s*(==|!=|>=|<=|>|<)\s*\d+$', re.I),
    re.compile(r'^len\(\s*\(?(?:to_lower\(|to_upper\()?(body|header|all|content_type|location|response|interactsh_protocol|interactsh_request|oast)(?:_\d+)?\)?\)?\s*\)\s*(==|!=|>=|<=|>|<)\s*\d+$', re.I),
    re.compile(r'^contains(_all|_any)?\(\s*\(?(?:to_lower\(|to_upper\()?(body|header|all|content_type|location|response|interactsh_protocol|interactsh_request|oast)(?:_\d+)?\)?\)?\s*,\s*(\'[^\']*\'|"[^"]*")(\s*,\s*(\'[^\']*\'|"[^"]*"))*\)$', re.I),
    re.compile(r'^regex\((\'[^\']*\'|"[^"]*")\s*,\s*\(?(?:to_lower\(|to_upper\()?(body|header|all|content_type|location|response|interactsh_protocol|interactsh_request|oast)(?:_\d+)?\)?\)?\)$', re.I),
    re.compile(r'^\s*(?:to_lower\(|to_upper\()?(body|header|all|content_type|location|response|interactsh_protocol|interactsh_request|oast)(?:_\d+)?\)?\s*(==|!=)\s*(\'[^\']*\'|"[^"]*")$', re.I),
    re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\s*(==|!=)\s*(\'[^\']*\'|"[^"]*")$'),
]
NEG_ATOM = re.compile(r'^!\s*(.+)$')

BUILTINS = {
    'BaseURL', 'RootURL', 'Hostname', 'Host', 'Port', 'Scheme',
    'randstr', 'target', 'port', 'callback_host', 'callback_port',
    'interactsh-url', 'interactsh_url',
}
PLACEHOLDER_RE = re.compile(r'\{\{([^}]+)\}\}')


def check_placeholders(s):
    for m in PLACEHOLDER_RE.finditer(s or ''):
        if m.group(1).strip() not in BUILTINS:
            return False
    return True


def split_top(e, op):
    parts, depth, quote, cur = [], 0, None, []
    i = 0
    while i < len(e):
        c = e[i]
        if quote:
            cur.append(c)
            if c == quote and (i == 0 or e[i - 1] != '\\'):
                quote = None
        elif c in '\'"':
            quote = c
            cur.append(c)
        elif c == '(':
            depth += 1
            cur.append(c)
        elif c == ')':
            depth -= 1
            cur.append(c)
        elif depth == 0 and e.startswith(op, i):
            parts.append("".join(cur))
            cur = []
            i += len(op)
            continue
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def valid_dsl_expr(e):
    e = e.strip()
    if not e:
        return False
    for p in split_top(e, '||'):
        if len(split_top(p, '&&')) > 1:
            if not all(valid_dsl_expr(x) for x in split_top(p, '&&')):
                return False
            continue
        if not valid_dsl_atom(p):
            return False
    return True


def valid_dsl_atom(a):
    a = a.strip()
    m = NEG_ATOM.match(a)
    if m and not a.startswith('!='):
        return valid_dsl_atom(m.group(1))
    for r in ATOM_RES:
        if r.match(a):
            return True
    return False


BAD_RE = re.compile(r'\(\?[=!<]|\(\?>|\\[1-9]|\\Z|\*\+|\+\+|\?\+')


def re_ok(p):
    if BAD_RE.search(p):
        return False
    try:
        re.compile(p)
        return True
    except re.error:
        return False


def subst_vars(s, variables):
    if not isinstance(s, str):
        return s
    for k, v in variables.items():
        s = s.replace('{{' + k + '}}', v)
    return s


def extract_variables(d):
    raw = d.get('variables')
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return None
    out = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
            return None
        out[k] = str(v)
    return out


def static_vars(variables):
    return {k: v for k, v in (variables or {}).items() if '{{' not in v}


def parse_payloads(block):
    p = block.get('payloads')
    attack = (block.get('attack') or '').lower()
    if p is None:
        return [], ''
    if attack not in ('', 'clusterbomb', 'pitchfork', 'batteringram'):
        return None, 'attack:' + attack
    if not isinstance(p, dict) or not p:
        return None, 'payloads'
    out = []
    combos = 1
    for k, vals in p.items():
        if not isinstance(k, str) or not isinstance(vals, list) or not vals:
            return None, 'payloads'
        svals = [str(v) for v in vals if isinstance(v, (str, int, float))]
        if not svals or len(svals) > 256:
            return None, 'payloads'
        out.append({'name': k, 'values': svals})
        combos *= len(svals)
    if attack == 'pitchfork':
        combos = min(len(x['values']) for x in out)
    if attack == 'batteringram':
        combos = len(out[0]['values'])
    if combos > 256:
        return None, 'payloads-big'
    return out, attack


def clean_str2(s, variables):
    if s is None:
        return None
    s = s.replace('{{BaseURL}}', '').replace('{{RootURL}}', '')
    return s


def convert_request_block(block, variables):
    for k in ('race', 'host', 'req-condition'):
        if k in block:
            return None, k
    payloads, attack = parse_payloads(block)
    if payloads is None:
        return None, attack
    redirects = bool(block.get('redirects', False))
    if 'raw' in block:
        raws = block['raw']
        if isinstance(raws, str):
            raws = [raws]
        if not isinstance(raws, list) or not raws:
            return None, 'raw'
        out = []
        for raw in raws:
            if not isinstance(raw, str):
                return None, 'raw'
            if unsupported_helper(raw):
                return None, 'helper:' + unsupported_helper(raw)
            lines = raw.splitlines()
            # 剥离注解行(@timeout/@Host/@tls-sni 等), 纯注解条目跳过
            while lines and lines[0].strip().startswith('@'):
                lines.pop(0)
            raw = '\n'.join(lines)
            if not raw.strip():
                continue
            first = raw.strip().splitlines()[0] if raw.strip() else ''
            parts = first.split()
            target = parts[1] if len(parts) >= 2 else ''
            if not target.startswith('/') and '{{' not in target:
                return None, 'raw-line'
            out.append({'raw': raw, 'redirects': redirects})
            if payloads:
                out[-1]['payloads'] = payloads
                out[-1]['attack'] = attack
        return out, None
    method = (block.get('method') or 'GET').upper()
    if method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'):
        return None, 'method'
    paths = block.get('path')
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or not paths:
        return None, 'no-path'
    headers = block.get('headers') or {}
    if not isinstance(headers, dict):
        return None, 'headers'
    body = block.get('body')
    if not isinstance(body, (str, type(None))):
        return None, 'body'
    for hk, hv in headers.items():
        if not isinstance(hv, str):
            return None, 'header-var'
    out = []
    for p in paths:
        if not isinstance(p, str):
            return None, 'path'
        sp = clean_str2(p, variables)
        if unsupported_helper(sp):
            return None, 'helper:' + unsupported_helper(sp)
        sp = (sp or '').strip()
        if not sp:
            if p.strip().rstrip('/') in ('{{BaseURL}}', '{{RootURL}}'):
                sp = '/'
            else:
                continue
        if re.match(r'^https?://', sp, re.I):
            return None, 'abs-url'
        if not sp.startswith('/'):
            sp = '/' + sp
        ent = {
            'method': method, 'path': sp,
            'headers': {k: (v if isinstance(v, str) else str(v)) for k, v in headers.items()},
            'body': body or '',
            'redirects': redirects,
        }
        if unsupported_helper(ent['body']):
            return None, 'helper:' + unsupported_helper(ent['body'])
        for hv in ent['headers'].values():
            if unsupported_helper(hv):
                return None, 'helper:' + unsupported_helper(hv)
        if payloads:
            ent['payloads'] = payloads
            ent['attack'] = attack
        out.append(ent)
    if not out:
        return None, 'path-empty'
    return out, None


def convert_matchers(block, variables):
    sv = static_vars(variables)
    mcondition = (block.get('matchers-condition') or 'or').lower()
    if mcondition not in ('and', 'or'):
        return None, 'mcond'
    matchers = block.get('matchers')
    if not isinstance(matchers, list) or not matchers:
        return None, 'no-matchers'
    out = []
    for m in matchers:
        if not isinstance(m, dict):
            return None, 'matcher'
        if m.get('internal'):
            continue
        mt = (m.get('type') or '').lower()
        part = (m.get('part') or 'body').lower()
        if part in ('status',):
            part = 'body'
        if part == 'headers':
            part = 'header'
        if part == 'interactsh_protocol':
            if mt not in ('word', 'regex'):
                return None, 'oast-part'
            vals = m.get('words') if mt == 'word' else m.get('regex')
            if not isinstance(vals, list) or not vals:
                return None, 'oast-matcher'
            out.append({'type': 'oast', 'words': [str(v) for v in vals]})
            continue
        if part == 'interactsh_request':
            if mt == 'word':
                vals = m.get('words')
                if not isinstance(vals, list) or not vals:
                    return None, 'oast-matcher'
                d = {'type': 'oast_request', 'words': [str(v) for v in vals]}
                if m.get('case-insensitive'):
                    d['ci'] = True
                out.append(d)
            elif mt == 'regex':
                regs = m.get('regex')
                if not isinstance(regs, list) or not regs or not all(isinstance(x, str) and re_ok(x) for x in regs):
                    return None, 'oast-matcher'
                out.append({'type': 'oast_request', 'regex': [str(x) for x in regs]})
            else:
                return None, 'oast-part'
            continue
        if part not in ('body', 'header', 'all', '') and not re.match(
                r'^(body|header|all|content_type|location|response)(_\d+)?$', part):
            return None, 'part:' + part
        neg = bool(m.get('negative'))
        if mt == 'status':
            st = m.get('status')
            if not isinstance(st, list) or not all(isinstance(x, int) for x in st):
                return None, 'status'
            out.append({'type': 'status', 'status': st})
        elif mt == 'word':
            words = m.get('words')
            if not isinstance(words, list) or not words or not all(isinstance(w, str) for w in words):
                return None, 'word'
            words = [subst_vars(w, sv) for w in words]
            for w in words:
                if unsupported_helper(w):
                    return None, 'helper:' + unsupported_helper(w)
            d = {'type': 'word', 'part': part, 'words': words}
            if m.get('case-insensitive'):
                d['ci'] = True
            out.append(d)
        elif mt == 'regex':
            raw_regs = m.get('regex')
            if not isinstance(raw_regs, list) or not raw_regs or not all(isinstance(x, str) for x in raw_regs):
                return None, 'regex'
            regs = [subst_vars(x, sv) for x in raw_regs]
            if not all(('{{' in x) or re_ok(x) for x in regs):
                return None, 'regex'
            out.append({'type': 'regex', 'part': part, 'regex': regs})
        elif mt == 'size':
            sz = m.get('size')
            if not isinstance(sz, list) or not all(isinstance(x, int) for x in sz):
                return None, 'size'
            out.append({'type': 'size', 'size': sz})
        elif mt == 'dsl':
            dsl = m.get('dsl')
            if not isinstance(dsl, list) or not dsl:
                return None, 'dsl'
            if not all(isinstance(x, str) and valid_dsl_expr(x) for x in dsl):
                return None, 'dsl-complex'
            d = {'type': 'dsl', 'dsl': [subst_vars(x, sv) for x in dsl]}
            if (m.get('condition') or 'or').lower() == 'and':
                d['cond'] = 'and'
            out.append(d)
        else:
            return None, 'mtype:' + (mt or '?')
        if neg:
            out[-1]['negative'] = True
    if not out:
        return None, 'no-matchers'
    return {'mcond': mcondition, 'matchers': out}, None


PART_TOKEN_RE = re.compile(
    r'(?<![A-Za-z0-9_])(body|header|all|content_type|location|response|interactsh_protocol|interactsh_request|oast)(?!_\d)(?![A-Za-z0-9_])',
    re.I)


def _idx_part(part, idx):
    p = part.lower()
    if p in ('interactsh_protocol', 'interactsh_request', 'oast'):
        return p
    if re.search(r'_\d+$', p):
        return p
    return '%s_%d' % (p, idx)


def _q(s):
    return "'" + str(s).replace('\\', '\\\\').replace("'", "\\'") + "'"


def matcher_to_dsl(m, idx, sv):
    """把单个 nuclei matcher 转换为索引 DSL 表达式(失败返回 None)"""
    if not isinstance(m, dict) or m.get('internal'):
        return None
    mt = (m.get('type') or '').lower()
    part = (m.get('part') or 'body').lower()
    if part == 'headers':
        part = 'header'
    if part == 'interactsh_protocol':
        vals = m.get('words') if mt == 'word' else (m.get('regex') if mt == 'regex' else None)
        if not vals:
            return None
        if mt == 'word':
            return ' || '.join('interactsh_protocol == %s' % _q(v) for v in vals)
        return ' || '.join('regex(%s, interactsh_protocol)' % _q(v) for v in vals)
    if part == 'interactsh_request':
        vals = m.get('words') if mt == 'word' else m.get('regex')
        if not vals:
            return None
        if mt == 'word':
            if m.get('case-insensitive'):
                return ' || '.join('contains(to_lower(interactsh_request), %s)' % _q(str(v).lower()) for v in vals)
            return ' || '.join('contains(interactsh_request, %s)' % _q(v) for v in vals)
        return ' || '.join('regex(%s, interactsh_request)' % _q(v) for v in vals)
    if mt == 'oast':
        words = m.get('words') or []
        if not words:
            return "oast == 'true'"
        return ' || '.join('interactsh_protocol == %s' % _q(w) for w in words)
    if mt == 'oast_request':
        words = m.get('words') or []
        if words:
            if m.get('case-insensitive'):
                return ' || '.join('contains(to_lower(interactsh_request), %s)' % _q(str(w).lower()) for w in words)
            return ' || '.join('contains(interactsh_request, %s)' % _q(w) for w in words)
        regs = m.get('regex') or []
        if regs:
            return ' || '.join('regex(%s, interactsh_request)' % _q(r) for r in regs)
        return "oast == 'true'"
    if part not in ('body', 'header', 'all', 'content_type', 'location', 'response') and \
            not re.match(r'^(body|header|all|content_type|location|response)(_\d+)?$', part):
        return None
    p = _idx_part(part, idx)
    if mt == 'status':
        st = m.get('status') or []
        if not st:
            return None
        return ' || '.join('status_code_%d == %d' % (idx, int(s)) for s in st)
    if mt == 'word':
        words = [subst_vars(w, sv) for w in (m.get('words') or [])]
        if not words:
            return None
        if m.get('case-insensitive'):
            return ' || '.join('contains(to_lower(%s), %s)' % (p, _q(str(w).lower())) for w in words)
        return ' || '.join('contains(%s, %s)' % (p, _q(w)) for w in words)
    if mt == 'regex':
        regs = [subst_vars(r, sv) for r in (m.get('regex') or [])]
        if not regs:
            return None
        return ' || '.join('regex(%s, %s)' % (_q(r), p) for r in regs)
    if mt == 'size':
        sz = m.get('size') or []
        if not sz:
            return None
        return ' || '.join('len(%s) == %d' % (p, int(x)) for x in sz)
    if mt == 'dsl':
        exprs = [subst_vars(e, sv) for e in (m.get('dsl') or [])]
        if not exprs:
            return None
        out = [PART_TOKEN_RE.sub(lambda mm: _idx_part(mm.group(1), idx), e) for e in exprs]
        cond = (m.get('condition') or 'or').lower()
        return (' && ' if cond == 'and' else ' || ').join('(%s)' % x for x in out)
    return None


def block_condition_expr(block, idx, sv):
    """把一个 http/tcp 块的所有 matcher 合成为该响应的 DSL 条件表达式"""
    if not isinstance(block, dict):
        return None, False
    ms = block.get('matchers') or []
    cond = (block.get('matchers-condition') or 'or').lower()
    parts = []
    oast = False
    for m in ms:
        if not isinstance(m, dict):
            return None, False
        if m.get('internal'):
            continue
        e = matcher_to_dsl(m, idx, sv)
        if e is None:
            return None, False
        if m.get('negative'):
            e = '!(' + e + ')'
        parts.append(e)
        blob = json.dumps(m).lower()
        if 'interactsh' in blob or '"oast' in blob or 'oast"' in blob:
            oast = True
    if not parts:
        return 'true', oast
    if cond == 'and':
        return ' && '.join('(%s)' % p for p in parts), oast
    return ' || '.join('(%s)' % p for p in parts), oast


FLOW_TOKEN = re.compile(r'http\(\s*(\d+)\s*\)')


def split_simple_flow(flow):
    """http(N)->H<N>; 含高级语法(变量/循环/函数)则返回 None"""
    s = FLOW_TOKEN.sub(lambda m: 'H%s' % m.group(1), flow or '')
    rest = re.sub(r'H\d+', '', s)
    if re.search(r'[A-Za-z_]', rest):
        return None
    return s


def convert_tcp(d):
    blocks = d.get('tcp')
    if not isinstance(blocks, list) or not blocks or len(blocks) > 6:
        return None, 'tcp'
    sv = static_vars(extract_variables(d) or {})
    reqs, exprs = [], []
    oast = False
    for i, b in enumerate(blocks, 1):
        if not isinstance(b, dict):
            return None, 'tcp'
        inputs = b.get('inputs')
        if not isinstance(inputs, list) or not inputs:
            return None, 'tcp'
        data = ''
        for inp in inputs:
            if isinstance(inp, dict) and isinstance(inp.get('data'), str):
                data += inp['data']
            elif isinstance(inp, str):
                data += inp
            else:
                return None, 'tcp'
        if re.search(r'generate_java_gadget|concat\(', data):
            return None, 'tcp-helper'
        if unsupported_helper(data):
            return None, 'helper:' + unsupported_helper(data)
        if 'interactsh' in data.lower():
            oast = True
        reqs.append({'proto': 'tcp', 'payload': data})
        e, bo = block_condition_expr(b, i, sv)
        if e is None:
            return None, 'tcp-matcher'
        exprs.append(e)
        oast = oast or bo
    expr = ' && '.join('(%s)' % x for x in exprs) if exprs else 'true'
    info = d.get('info') or {}
    sev = str(info.get('severity') or 'high').lower()
    if sev not in ('info', 'low', 'medium', 'high', 'critical'):
        sev = 'high'
    return {
        'id': d.get('id') or '',
        'name': str(info.get('name') or d.get('id') or '').strip(),
        'sev': sev,
        'requests': reqs,
        'mcond': 'and',
        'matchers': [{'type': 'dsl', 'dsl': [expr]}],
        'oast': oast,
    }, None


HELPER_RE = re.compile(r'\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(')
SUPPORTED_HELPERS = {
    'rand_int', 'rand_text_alpha', 'rand_text', 'rand_text_alphanumeric', 'rand_text_numeric',
    'rand_number', 'rand_base', 'randbase', 'rand_char', 'to_lower', 'to_upper',
    'md5', 'sha1', 'sha256', 'base64', 'base64_decode', 'hex_decode',
    'url_encode', 'urlencode', 'url_decode', 'urldecode', 'repeat', 'unix_time',
    'trim_prefix', 'trim_suffix', 'concat', 'replace', 'to_number', 'len',
}


def unsupported_helper(s):
    if not isinstance(s, str):
        return None
    for m in HELPER_RE.finditer(s):
        if m.group(1) not in SUPPORTED_HELPERS:
            return m.group(1)
    return None


def convert_extractors(block):
    out = []
    for ex in block.get('extractors') or []:
        if not isinstance(ex, dict):
            return None
        et = (ex.get('type') or '').lower()
        if et not in ('regex', 'json', 'kval'):
            return None
        d = {'type': et, 'internal': bool(ex.get('internal'))}
        if ex.get('name'):
            d['name'] = str(ex['name'])
        if et == 'regex':
            rx = ex.get('regex')
            if not isinstance(rx, list) or not rx:
                return None
            d['regex'] = [str(x) for x in rx]
            if isinstance(ex.get('group'), int):
                d['group'] = ex['group']
        elif et == 'json':
            js = ex.get('json')
            if not isinstance(js, list) or not js:
                return None
            d['json'] = [str(x) for x in js]
        else:
            kv = ex.get('kval')
            if not isinstance(kv, list) or not kv:
                return None
            d['kval'] = [str(x) for x in kv]
        if d['internal'] and not d.get('name'):
            return None
        out.append(d)
    return out


def convert(path):
    try:
        d = yaml.safe_load(open(path, encoding='utf-8'))
    except Exception:
        return None, 'yaml'
    if not isinstance(d, dict):
        return None, 'yaml'
    info = d.get('info') or {}
    if not isinstance(info, dict):
        return None, 'info'
    variables = extract_variables(d)
    if variables is None:
        return None, 'variables'
    for v in variables.values():
        u = unsupported_helper(v)
        if u:
            return None, 'helper:' + u
    sv = static_vars(variables)
    if 'tcp' in d:
        return convert_tcp(d)
    flow = d.get('flow')
    if flow is not None:
        s = split_simple_flow(flow)
        if s is None:
            return None, 'flow'
        reqs = d.get('http') or d.get('requests')
        if not isinstance(reqs, list) or not reqs or len(reqs) > 6:
            return None, 'flow'
        used = sorted({int(x) for x in re.findall(r'H(\d+)', s)})
        if not used or max(used) > len(reqs):
            return None, 'flow'
        requests_out, exprs = [], {}
        oast = False
        exts = []
        for i, block in enumerate(reqs, 1):
            if not isinstance(block, dict):
                return None, 'request'
            rq, why = convert_request_block(block, variables)
            if rq is None:
                return None, why
            requests_out.extend(rq)
            e, bo = block_condition_expr(block, i, sv)
            if e is None:
                return None, 'flow-matcher'
            exprs[i] = e
            oast = oast or bo
            ce = convert_extractors(block)
            if ce is None:
                return None, 'extractor'
            exts.extend(ce)
        combined = re.sub(r'H(\d+)', lambda m: '(' + exprs.get(int(m.group(1)), 'true') + ')', s)
        if not requests_out or len(requests_out) > 12:
            return None, 'too-many'
        sev = str(info.get('severity') or 'medium').lower()
        if sev not in ('info', 'low', 'medium', 'high', 'critical'):
            sev = 'medium'
        blob = json.dumps(requests_out).lower()
        oast = oast or 'interactsh' in blob
        rec = {
            'id': d.get('id') or os.path.basename(path)[:-5],
            'name': str(info.get('name') or d.get('id') or '').strip(),
            'sev': sev,
            'requests': requests_out,
            'mcond': 'and',
            'matchers': [{'type': 'dsl', 'dsl': [combined]}],
            'oast': oast,
        }
        if variables:
            rec['variables'] = variables
        if exts:
            rec['extractors'] = exts
        return rec, None
    reqs = d.get('http') or d.get('requests')
    if reqs is None:
        for k in ('tcp', 'ssl', 'udp', 'network', 'javascript', 'headless', 'code', 'file', 'whois', 'websocket', 'dns'):
            if k in d:
                return None, 'proto:' + k
        return None, 'no-request'
    if not isinstance(reqs, list) or not reqs:
        return None, 'no-request'
    if len(reqs) > 6:
        return None, 'multi-block'
    requests_out = []
    mr = None
    exts = []
    for block in reqs:
        if not isinstance(block, dict):
            return None, 'request'
        rq, why = convert_request_block(block, variables)
        if rq is None:
            return None, why
        requests_out.extend(rq)
        mout, why = convert_matchers(block, variables)
        if mout is not None and mr is None:
            mr = mout
        ce = convert_extractors(block)
        if ce is None:
            return None, 'extractor'
        exts.extend(ce)
    if mr is None:
        return None, 'no-matchers'
    if not requests_out or len(requests_out) > 12:
        return None, 'too-many'
    sev = str(info.get('severity') or 'medium').lower()
    if sev not in ('info', 'low', 'medium', 'high', 'critical'):
        sev = 'medium'
    blob = json.dumps(requests_out) + json.dumps(mr)
    oast = 'interactsh' in blob.lower()
    rec = {
        'id': d.get('id') or os.path.basename(path)[:-5],
        'name': str(info.get('name') or d.get('id') or '').strip(),
        'sev': sev,
        'requests': requests_out,
        'mcond': mr['mcond'],
        'matchers': mr['matchers'],
        'oast': oast,
    }
    if variables:
        rec['variables'] = variables
    if exts:
        rec['extractors'] = exts
    return rec, None


def main():
    skip = Counter()
    ok = Counter()
    with open(OUT, 'w', encoding='utf-8') as f:
        for name in sorted(os.listdir(POOL)):
            root = os.path.join(POOL, name)
            if not os.path.isdir(root):
                continue
            src = OFFICIAL_SRC if name == OFFICIAL_DIR else 'allforone/' + name
            n = 0
            for dp, _, fns in os.walk(root):
                for fn in fns:
                    if not fn.endswith(('.yaml', '.yml')):
                        continue
                    fp = os.path.join(dp, fn)
                    r, why = convert(fp)
                    if r is None:
                        skip[why] += 1
                        continue
                    rec = dict(r)
                    rec['src'] = src
                    rec['path'] = os.path.relpath(fp, root)
                    f.write(json.dumps(rec, ensure_ascii=False) + '\n')
                    n += 1
            ok[src] = n
            if n:
                print('%-58s converted=%-6d' % (src, n), flush=True)
    print('TOTAL converted: %d' % sum(ok.values()), flush=True)
    print('skip reasons:', skip.most_common(15), flush=True)


if __name__ == '__main__':
    main()
