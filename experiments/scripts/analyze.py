import csv, glob, re, statistics as st, datetime as d
T = lambda s: d.datetime.strptime(s.strip(), '%H:%M:%S.%f')
S = lambda a, b: (b - a).total_seconds()
sec = lambda x: d.timedelta(seconds=x)

def load(f):
    rows = []
    for r in csv.DictReader(open(f)):
        try: rows.append((T(r['time']), [int(r['node1']), int(r['node2']), int(r['node3'])]))
        except Exception: pass
    ev = {}
    for l in open(f.replace('.csv', '.events')):
        t, txt = l.strip().split(' ', 1); ev[txt.split()[0]] = (T(t), txt)
    return rows, ev

win = lambda rows, a, b: [x for x in rows if a <= x[0] <= b]
def rate(w, cols):
    return st.mean((w[-1][1][c] - w[0][1][c]) / S(w[0][0], w[-1][0]) for c in cols) if len(w) > 1 else float('nan')
def maxgap(w, c):   # longest time with no progress of 30+ counts
    if not w: return float('nan')
    ref, pt, best = w[0][1][c], w[0][0], 0.0
    for t, v in w[1:]:
        if v[c] - ref >= 30: best = max(best, S(pt, t)); ref, pt = v[c], t
    return max(best, S(pt, w[-1][0]))

def analyse(f):
    rows, ev = load(f)
    start, iso, heal, end = (ev[k][0] for k in ('START', 'ISOLATE', 'HEAL', 'END'))
    ii = int(re.search(r'isolating_idx=(\d)', ev['START'][1]).group(1))
    li = int(re.search(r'leader_idx=(\d)', ev['START'][1]).group(1))
    oth = [i for i in range(3) if i != ii]
    base = rate(win(rows, start + sec(3), iso - sec(1)), oth)
    degr = rate(win(rows, iso + sec(10), heal - sec(1)), oth)
    pause = max(maxgap(win(rows, iso - sec(1), iso + sec(20)), c) for c in oth)
    iw = win(rows, iso + sec(5), heal)
    frozen = iw[-1][1][ii] - iw[0][1][ii] if iw else float('nan')
    before = [x for x in rows if x[0] <= heal][-1][1][ii]
    rejoin = jump = float('nan')
    for t, v in rows:
        if t > heal and v[ii] - before >= 30: rejoin, jump = S(heal, t), v[ii] - before; break
    disrupt = max(maxgap(win(rows, heal, heal + sec(15)), c) for c in oth)
    post = rate(win(rows, heal + sec(12), end), oth)
    wr = win(rows, iso - sec(1), end)
    gap = max(S(a[0], b[0]) for a, b in zip(wr, wr[1:]))
    return dict(f=f.replace('.csv', ''), mode='leader' if ii == li else 'follower', base=base, degr=degr,
                drop=100 * (1 - degr / base), pause=pause, frozen=frozen, rejoin=rejoin, jump=jump,
                disrupt=disrupt, post=post, gap=gap, isolen=S(iso, heal), healen=S(heal, end))

files = sorted(glob.glob('leader_*.csv') + glob.glob('follower_*.csv'))
res = [analyse(f) for f in files]
hdr = ['f', 'mode', 'base', 'degr', 'drop', 'pause', 'frozen', 'rejoin', 'jump', 'disrupt', 'post', 'gap', 'isolen', 'healen']
print(' '.join(f'{h:>12}' for h in hdr))
for r in res:
    print(' '.join(f'{r[h]:>12.1f}' if isinstance(r[h], float) else f'{r[h]:>12}' for h in hdr))
print('\ncolumns: base/degr/post = counts per second; drop = % drop; pause = longest no-progress (s) after the block;')
print('frozen = counts the isolated node advanced; rejoin = s from heal to catch-up; jump = counts replayed;')
print('disrupt = longest no-progress on the majority during heal; gap = largest sampling gap; isolen/healen = phase lengths (s)')
for m in ('leader', 'follower'):
    ok = [r for r in res if r['mode'] == m and r['gap'] < 3 and abs(r['healen'] - 40) < 5 and abs(r['isolen'] - 60) < 5]
    bad = [r['f'] for r in res if r['mode'] == m and r not in ok]
    print(f'\n{m}: {len(ok)} clean runs; excluded: {bad or "none"}')
    for k in ('base', 'degr', 'drop', 'pause', 'rejoin', 'post'):
        v = [r[k] for r in ok]
        if v: print(f'  {k:7} mean {st.mean(v):8.1f}   min {min(v):8.1f}   max {max(v):8.1f}')
