from flask import Flask, flash, request, render_template, abort, redirect, url_for
import os
import re
import ipaddress
import sqlite3
import subprocess
import time

BASE_DIR = os.path.dirname(__file__)
DB_DIR = os.path.join(BASE_DIR, 'data')
DB_FILE = os.path.join(DB_DIR, 'hosts.db')
GENERATED_DIR = os.path.join(BASE_DIR, 'generated')

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(GENERATED_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for flash messages


def get_db_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_default_settings():
    """Initialize default settings if not already set"""
    settings = {
        'rndc_path': '/usr/sbin/rndc',
        'checkzone_path': '/usr/sbin/named-checkzone',
        'rndc_key': '',
        'bind_reload_cmd': ''
    }
    conn = get_db_conn()
    cur = conn.cursor()
    for key, value in settings.items():
        cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()


def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS hosts (
        name TEXT PRIMARY KEY,
        aliases TEXT,
        ip TEXT
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')
    conn.commit()
    conn.close()


init_db()
init_default_settings()


HOST_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")


def valid_hostname(name):
    return bool(HOST_RE.match(name))


def valid_ip(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except Exception:
        return False


def get_all_entries(sort=None, order='asc'):
    conn = get_db_conn()
    cur = conn.cursor()
    q = 'SELECT name, aliases, ip FROM hosts'
    if sort in ('name', 'ip'):
        q += f' ORDER BY {sort} {"ASC" if order=="asc" else "DESC"}'
    cur.execute(q)
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        aliases = r['aliases'].split(',') if r['aliases'] else []
        aliases = [a for a in (a.strip() for a in aliases) if a]
        out.append({'name': r['name'], 'aliases': aliases, 'ip': r['ip'] or ''})
    return out


def get_setting(key, default=None):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('SELECT value FROM settings WHERE key=?', (key,))
    r = cur.fetchone()
    conn.close()
    if r:
        return r['value']
    return default

def check_zone_file(zone_name, zone_file):
    """Check zone file syntax using named-checkzone.
    Returns (success, error_message)
    """
    checkzone = get_setting('checkzone_path', '/usr/sbin/named-checkzone')
    if not os.path.exists(checkzone):
        return False, f"named-checkzone not found at {checkzone}"

    try:
        result = subprocess.run([checkzone, zone_name, zone_file], 
                              capture_output=True, text=True, check=True)
        return True, None
    except subprocess.CalledProcessError as e:
        return False, f"Zone check failed: {e.stderr or str(e)}"

def run_bind_command(cmd, zone=None):
    """Run an rndc command, returning (success, error_message)"""
    rndc = get_setting('rndc_path', '/usr/sbin/rndc')
    rndc_key = get_setting('rndc_key', '')
    reload_cmd = get_setting('bind_reload_cmd', '')

    if cmd == 'reload' and reload_cmd:
        # Use alternative reload command if configured
        try:
            subprocess.run(reload_cmd, shell=True, check=True, capture_output=True, text=True)
            return True, None
        except subprocess.CalledProcessError as e:
            return False, f"Reload failed: {e.stderr or str(e)}"

    if not os.path.exists(rndc):
        return False, f"rndc not found at {rndc}"

    args = [rndc]
    if rndc_key and os.path.exists(rndc_key):
        args.extend(['-k', rndc_key])
    
    args.append(cmd)
    if zone:
        args.append(zone)

    try:
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return True, None
    except subprocess.CalledProcessError as e:
        return False, f"rndc {cmd} failed: {e.stderr or str(e)}"

def update_bind_zones(zones, temp_files):
    """Update BIND zones with proper freeze/thaw cycle.
    zones: List of zone names
    temp_files: Dict mapping zone names to temporary file paths
    Returns (success, error_message)
    """
    # First check all zone files
    for zone, temp_file in temp_files.items():
        ok, err = check_zone_file(zone, temp_file)
        if not ok:
            return False, f"Zone {zone} check failed: {err}"

    for zone in zones:
        # Freeze zone to prevent journal updates during file replacement
        ok, err = run_bind_command('freeze', zone)
        if not ok:
            return False, f"Failed to freeze {zone}: {err}"

    # Wait briefly for any pending updates
    time.sleep(0.5)

    try:
        # Get zone file directory setting
        zone_dir = get_setting('zone_dir', GENERATED_DIR)

        # Move temp files to their final locations
        for zone, temp_file in temp_files.items():
            # Get zone file name based on zone
            if zone.endswith('.in-addr.arpa'):
                # Reverse zone: decide whether filename uses reversed octets or network octets
                labels = zone.replace('.in-addr.arpa', '').split('.')
                use_reversed = get_setting('reverse_use_reversed_ip', 'false') == 'true'
                if use_reversed:
                    network = '.'.join(labels)
                else:
                    network = '.'.join(reversed(labels))
                zone_format = get_setting('reverse_zone_format', 'db.{network}.in-addr.arpa')
                final_name = zone_format.format(network=network)
            else:
                # Forward zone
                zone_format = get_setting('forward_zone_format', 'db.{domain}')
                final_name = zone_format.format(domain=zone)

            final_path = os.path.join(zone_dir, final_name)
            os.rename(temp_file, final_path)

        # Now reload the zones one by one
        for zone in zones:
            ok, err = run_bind_command('reload', zone)
            if not ok:
                return False, f"Failed to reload {zone}: {err}"

    except Exception as e:
        return False, f"Failed to update zone files: {str(e)}"
    finally:
        # Always try to thaw zones, even if reload failed
        for zone in zones:
            ok, err = run_bind_command('thaw', zone)
            if not ok:
                return False, f"Failed to thaw {zone}: {err}"
            
        # Clean up any remaining temp files
        for temp_file in temp_files.values():
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except:
                pass

    return True, None


def set_setting(key, value):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

def add_entry_db(name, aliases, ip):
    conn = get_db_conn()
    try:
        conn.execute('INSERT INTO hosts (name, aliases, ip) VALUES (?, ?, ?)', (name, ','.join(aliases), ip))
        conn.commit()
        return True, None
    except sqlite3.IntegrityError as e:
        return False, 'exists'
    finally:
        conn.close()


def update_entry_db(original, name, aliases, ip):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('UPDATE hosts SET name=?, aliases=?, ip=? WHERE name=?', (name, ','.join(aliases), ip, original))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return changed > 0


def delete_entry_db(name):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('DELETE FROM hosts WHERE name=?', (name,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return changed > 0


@app.route('/')
def index():
    sort = request.args.get('sort')
    order = request.args.get('order', 'asc')
    entries = get_all_entries(sort=sort, order=order)
    # no templates needed anymore
    tlist = []
    msg = request.args.get('msg', '')
    # collect recent conflict reports
    conflicts = []
    try:
        for fn in os.listdir(GENERATED_DIR):
            if fn.endswith('.conflicts'):
                path = os.path.join(GENERATED_DIR, fn)
                try:
                    with open(path, 'r') as cf:
                        lines = [l.strip() for l in cf.readlines() if l.strip()]
                        if lines:
                            conflicts.append({'file': fn, 'lines': lines})
                except Exception:
                    continue
    except Exception:
        conflicts = []
    # surface current settings summary
    settings_summary = {
        'base_domain': get_setting('base_domain','avexys.com'),
        'reverse_cidr': get_setting('reverse_cidr','10.255.255.0/24')
    }
    return render_template('index.html', entries=entries, templates=tlist, message=msg, sort=sort, order=order, conflicts=conflicts, settings=settings_summary)


@app.route('/add', methods=['POST'])
def add():
    name = request.form.get('name','').strip()
    aliases = [a.strip() for a in request.form.get('aliases','').split(',') if a.strip()]
    ip = request.form.get('ip','').strip()
    if not valid_hostname(name):
        flash('Invalid hostname format', 'error')
        return redirect(url_for('index'))
    if ip and not valid_ip(ip):
        flash('Invalid IP address format', 'error')
        return redirect(url_for('index'))
    for a in aliases:
        if not valid_hostname(a):
            flash(f'Invalid alias format: {a}', 'error')
            return redirect(url_for('index'))
    ok, err = add_entry_db(name, aliases, ip)
    if not ok:
        flash('An entry with this hostname already exists', 'error')
        return redirect(url_for('index'))
    try:
        generate_all_from_settings()
        flash(f'Successfully added host {name}', 'success')
    except Exception as e:
        flash(f'Host added but zone generation failed: {str(e)}', 'warning')
    return redirect(url_for('index'))


@app.route('/edit', methods=['POST'])
def edit():
    original = request.form.get('original_name','').strip()
    name = request.form.get('name','').strip()
    aliases = [a.strip() for a in request.form.get('aliases','').split(',') if a.strip()]
    ip = request.form.get('ip','').strip()
    if not valid_hostname(name):
        flash('Invalid hostname format', 'error')
        return redirect(url_for('index'))
    if ip and not valid_ip(ip):
        flash('Invalid IP address format', 'error')
        return redirect(url_for('index'))
    for a in aliases:
        if not valid_hostname(a):
            flash(f'Invalid alias format: {a}', 'error')
            return redirect(url_for('index'))
    changed = update_entry_db(original, name, aliases, ip)
    if not changed:
        flash('Host not found', 'error')
        return redirect(url_for('index'))
    try:
        generate_all_from_settings()
        flash(f'Successfully updated host {name}', 'success')
    except Exception as e:
        flash(f'Host updated but zone generation failed: {str(e)}', 'warning')
    return redirect(url_for('index'))


@app.route('/delete', methods=['POST'])
def delete():
    name = request.form.get('name','').strip()
    if not name:
        flash('No hostname provided', 'error')
        return redirect(url_for('index'))
    deleted = delete_entry_db(name)
    if not deleted:
        flash('Host not found', 'error')
        return redirect(url_for('index'))
    try:
        generate_all_from_settings()
        flash(f'Successfully deleted host {name}', 'success')
    except Exception as e:
        flash(f'Host deleted but zone generation failed: {str(e)}', 'warning')
    return redirect(url_for('index'))


def parse_zone_text(text):
    """Parse simple zone file text to extract A records and CNAMEs.
    Returns list of entries: {'name':..., 'aliases':[...], 'ip':...}
    """
    origin = None
    a_records = {}
    cnames = {}
    last_name = None
    for raw in text.splitlines():
        line = raw.split(';',1)[0].strip()
        if not line:
            continue
        if line.startswith('$ORIGIN'):
            parts = re.split(r'\s+', line)
            if len(parts) >= 2:
                origin = parts[1].strip()
                if origin.endswith('.'):
                    origin = origin[:-1]
            continue
        parts = re.split(r'\s+', line)
        # if line starts with whitespace and name omitted, skip (hard to map)
        if len(parts) < 3:
            continue
        name, typ, val = parts[0], parts[1].upper(), parts[2]
        if name == '@' and origin:
            name = origin
        if name.endswith('.'):
            name = name[:-1]
        # normalize target value
        if val.endswith('.'):
            val = val[:-1]
        # strip origin suffix from val if present
        if origin and val.endswith('.' + origin):
            val = val[:-(len(origin)+1)]
        elif origin and val == origin:
            val = origin

        if typ == 'A':
            # value should be IP
            a_records[name] = val
        elif typ == 'CNAME':
            cnames[name] = val

    # Resolve CNAME chains to A-record names/ips
    resolved_aliases = {}  # alias -> (target_name, ip)
    for alias, target in cnames.items():
        seen = set()
        cur = target
        while True:
            if cur in seen:
                # loop
                cur = None
                break
            seen.add(cur)
            if cur in a_records:
                ip = a_records[cur]
                resolved_aliases[alias] = (cur, ip)
                break
            if cur in cnames:
                cur = cnames[cur]
                continue
            # cannot resolve to local A
            cur = None
            break

    # Build entries: for each A record name, collect aliases that resolved to it
    entries = []
    alias_map = {}
    for alias, (target_name, ip) in resolved_aliases.items():
        alias_map.setdefault(target_name, []).append(alias)

    for name, ip in a_records.items():
        aliases = alias_map.get(name, [])
        entries.append({'name': name, 'aliases': aliases, 'ip': ip})

    return entries

def generate_all_from_settings():
    # Generate forward and reverse zones using stored settings (no templates)
    base_domain = get_setting('base_domain', 'avexys.com')
    reverse_cidr = get_setting('reverse_cidr', '10.255.255.0/24')
    soa_primary = get_setting('soa_primary', 'utility01.' + base_domain)
    soa_admin = get_setting('soa_admin', 'dns-admin@' + base_domain)
    ttl = int(get_setting('ttl', '3600'))
    ns_records = [s.strip() for s in get_setting('ns_records', 'utility01.' + base_domain + ',utility02.' + base_domain).split(',') if s.strip()]

    # bump serial
    import time
    prev_serial = int(get_setting('soa_serial', '0'))
    # simple increment strategy: if prev_serial < today*100 then set to today*100 + 1 else increment
    today = int(time.strftime('%Y%m%d'))
    if prev_serial // 100 < today:
        serial = today * 100 + 1
    else:
        serial = prev_serial + 1
    set_setting('soa_serial', str(serial))

    # Get zone file settings
    zone_dir = get_setting('zone_dir', GENERATED_DIR)
    forward_zone_format = get_setting('forward_zone_format', 'db.{domain}')
    reverse_zone_format = get_setting('reverse_zone_format', 'db.{network}.in-addr.arpa')

    # Create output directory if needed
    os.makedirs(zone_dir, exist_ok=True)

    # Forward zone filename
    forward_name = forward_zone_format.format(domain=base_domain)
    forward_path = os.path.join(zone_dir, forward_name)

    header = []
    header.append('$ORIGIN .')
    header.append(f'$TTL {ttl}\t; default TTL')
    header.append(f'{base_domain}\tIN SOA\t{soa_primary}. {soa_admin.replace("@",".")}. (')
    header.append(f"\t{serial} ; serial")
    header.append('\t604800 ; refresh')
    header.append('\t86400 ; retry')
    header.append('\t2419200 ; expire')
    header.append(f'\t{ttl} ; minimum')
    header.append('\t)')
    for ns in ns_records:
        header.append(f'\tNS\t{ns}.')

    # then $ORIGIN for forward
    header.append(f'$ORIGIN {base_domain}.')
    header.append(f'$TTL {max(1200, ttl//3)}\t; zone TTL')

    # build forward records
    entries = get_all_entries()
    records = []
    conflicts = []
    # detect a-record fqdn set
    a_names = set()
    for e in entries:
        if e.get('ip'):
            nm = e['name'].rstrip('.')
            fqdn = nm if '.' in nm else f"{nm}.{base_domain}"
            a_names.add(fqdn)

    for e in entries:
        name = e['name']
        ip = e.get('ip','')
        aliases = e.get('aliases',[]) or []
        # owner label relative to origin
        def owner_label(n):
            nn = n.rstrip('.')
            if '.' in nn:
                if nn == base_domain:
                    return '@'
                if nn.endswith('.' + base_domain):
                    return nn[:-(len('.' + base_domain))]
                return nn
            return nn

        owner = owner_label(name)
        if ip:
            records.append(f"{owner}\tA\t{ip}")
            for a in aliases:
                a_fqdn = a.rstrip('.') if '.' in a else f"{a}.{base_domain}"
                a_owner = owner_label(a)
                if a_fqdn in a_names:
                    conflicts.append(f"Alias {a_fqdn} skipped for {name}: has its own A record")
                    records.append(f"; SKIPPED CNAME {a_owner} -> {owner} (collision with existing A)")
                else:
                    records.append(f"{a_owner}\tCNAME\t{owner}")
        else:
            for a in aliases:
                a_fqdn = a.rstrip('.') if '.' in a else f"{a}.{base_domain}"
                a_owner = owner_label(a)
                if a_fqdn in a_names:
                    conflicts.append(f"Alias {a_fqdn} skipped for {name}: alias has its own A record")
                    records.append(f"; SKIPPED CNAME {a_owner} -> {owner} (collision with existing A)")
                else:
                    records.append(f"{a_owner}\tCNAME\t{owner}")

    # write forward zone
    forward_root_block = get_setting('forward_root_block', '') or ''
    forward_end_block = get_setting('forward_end_block', '') or ''

    # Split header into root part and domain part
    root_header = []
    domain_header = []
    in_root = True
    for line in header:
        if line.startswith(f'$ORIGIN {base_domain}.'):
            in_root = False
        if in_root:
            root_header.append(line)
        else:
            domain_header.append(line)

    # Write forward zone to temp file first
    temp_forward = forward_path + '.tmp'
    os.umask(0)
    descriptor = os.open(temp_forward, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o775)
    with open(descriptor, 'w') as f:
        # Write root section header
        f.write('; Root zone configuration\n')
        f.write('\n'.join(root_header) + '\n\n')
        
        # Write root block before domain section
        if forward_root_block:
            f.write('; Custom root zone records\n')
            # ensure trailing newline
            if not forward_root_block.endswith('\n'):
                forward_root_block = forward_root_block + '\n'
            f.write(forward_root_block + '\n')

        # Write domain section header
        f.write('; Domain zone configuration\n')
        f.write('\n'.join(domain_header) + '\n\n')

        # Write zone records
        f.write('; Managed host records\n')
        f.write('\n'.join(records) + '\n')

        # Write end block if present
        if forward_end_block:
            f.write('\n; Custom zone records\n')
            if not forward_end_block.endswith('\n'):
                forward_end_block = forward_end_block + '\n'
            f.write(forward_end_block)

    # save conflicts
    if conflicts:
        cfpath = os.path.join(os.path.dirname(forward_path), f"{forward_name}.conflicts")
        with open(cfpath, 'w') as cf:
            for c in conflicts:
                cf.write(c + '\n')

    # generate reverse
    try:
        net = ipaddress.ip_network(reverse_cidr, strict=False)
    except Exception:
        return [forward_path]

    # only support prefixes on octet boundaries (/8,/16,/24/...)
    if net.version != 4 or (net.prefixlen % 8) != 0:
        # fallback: do not generate reverse
        return [forward_path]

    prefix_octets = net.prefixlen // 8
    net_octets = net.network_address.exploded.split('.')[:prefix_octets]
    rev_parts = list(reversed(net_octets))
    reverse_origin = '.'.join(rev_parts) + '.in-addr.arpa'
    network_part = '.'.join(net_octets)  # For filename format
    # Optionally use the reversed-octet IP for filename (e.g. 255.255.10)
    use_reversed = get_setting('reverse_use_reversed_ip', 'false') == 'true'
    if use_reversed:
        network_for_filename = '.'.join(rev_parts)
    else:
        network_for_filename = network_part
    reverse_name = reverse_zone_format.format(network=network_for_filename)
    reverse_path = os.path.join(zone_dir, reverse_name)

    rev_header = []
    rev_header.append('$ORIGIN .')
    rev_header.append(f'$TTL {ttl}\t; default TTL')
    rev_header.append(f'{reverse_origin}\tIN SOA\t{soa_primary}. {soa_admin.replace("@",".")}. (')
    rev_header.append(f"\t{serial} ; serial")
    rev_header.append('\t604800 ; refresh')
    rev_header.append('\t86400 ; retry')
    rev_header.append('\t2419200 ; expire')
    rev_header.append(f'\t{ttl} ; minimum')
    rev_header.append('\t)')
    for ns in ns_records:
        rev_header.append(f'\tNS\t{ns}.')

    # origin for reverse
    rev_header.append(f'$ORIGIN {reverse_origin}.')
    rev_header.append(f'$TTL {max(1200, ttl//3)}\t; zone TTL')

    # Collect and sort reverse records by IP
    rev_entries = []
    for e in entries:
        ip = e.get('ip','')
        if not ip:
            continue
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version != 4:
                continue
        except Exception:
            continue
        if addr in net:
            octets = ip.split('.')
            label_parts = octets[prefix_octets:]
            if not label_parts:
                continue
            label = '.'.join(label_parts)
            name = e['name']
            fqdn = name if '.' in name else f"{name}.{base_domain}"
            if not fqdn.endswith('.'):
                fqdn = fqdn + '.'
            rev_entries.append((octets, label, fqdn))
    
    # Sort by IP octets for consistent ordering
    rev_entries.sort(key=lambda x: [int(o) for o in x[0]])
    
    # Generate records in sorted order
    rev_records = [f"{label}\tPTR\t{fqdn}" for _, label, fqdn in rev_entries]

    # Write reverse zone to temp file
    temp_reverse = reverse_path + '.tmp'
    descriptor = os.open(temp_reverse, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o775)
    with open(descriptor, 'w') as f:
        f.write('\n'.join(rev_header) + '\n\n')
        f.write('\n'.join(rev_records) + '\n')

    # Attempt to update BIND with both zones
    try:
        zones_to_update = [base_domain, reverse_origin]
        temp_files = {
            base_domain: temp_forward,
            reverse_origin: temp_reverse
        }
        ok, err = update_bind_zones(zones_to_update, temp_files)
        if ok:
            # Only move files into place if BIND accepts them
            # os.rename(temp_forward, forward_path)
            # os.rename(temp_reverse, reverse_path)
            return [forward_path, reverse_path]
        else:
            # Clean up temp files
            try:
                os.unlink(temp_forward)
                os.unlink(temp_reverse)
            except:
                pass
            raise Exception(f"Failed to update BIND: {err}")
    except Exception as e:
        # Clean up temp files
        try:
            os.unlink(temp_forward)
            os.unlink(temp_reverse)
        except:
            pass
        raise


@app.route('/import', methods=['GET', 'POST'])
def import_zone():
    if request.method == 'GET':
        # list available files in templates and generated
        try:
            templates = [f for f in os.listdir(TEMPLATES_DIR) if os.path.isfile(os.path.join(TEMPLATES_DIR, f))]
        except Exception:
            templates = []
        try:
            generated = [f for f in os.listdir(GENERATED_DIR) if os.path.isfile(os.path.join(GENERATED_DIR, f))]
        except Exception:
            generated = []
        return render_template('import.html', templates=templates, generated=generated)

    # POST: import selected or uploaded file
    src = request.form.get('source')
    uploaded = request.files.get('file')
    text = ''
    if uploaded and uploaded.filename:
        text = uploaded.read().decode('utf-8', errors='ignore')
    elif src:
        # check templates first then generated
        for d in (TEMPLATES_DIR, GENERATED_DIR):
            path = os.path.join(d, src)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    text = f.read()
                break
    if not text:
        return redirect(url_for('index', msg='No file selected'))

    entries = parse_zone_text(text)
    added = 0
    updated = 0
    for e in entries:
        name = e['name']
        aliases = e.get('aliases', [])
        ip = e.get('ip', '')
        # validate minimally
        if not valid_hostname(name) or (ip and not valid_ip(ip)):
            continue
        ok, err = add_entry_db(name, aliases, ip)
        if ok:
            added += 1
        else:
            # exists -> update
            changed = update_entry_db(name, name, aliases, ip)
            if changed:
                updated += 1

    return redirect(url_for('index', msg=f'Imported {added} added, {updated} updated'))


@app.route('/settings', methods=['GET', 'POST'])
def settings_ui():
    if request.method == 'GET':
        base_domain = get_setting('base_domain', 'avexys.com')
        reverse_cidr = get_setting('reverse_cidr', '10.255.255.0/24')
        soa_primary = get_setting('soa_primary', 'utility01.avexys.com')
        soa_admin = get_setting('soa_admin', 'dns-admin@avexys.com')
        forward_root_block = get_setting('forward_root_block', '')
        forward_end_block = get_setting('forward_end_block', '')
        ttl = get_setting('ttl', '3600')
        ns_records = get_setting('ns_records', 'utility01.avexys.com,utility02.avexys.com')
        zone_dir = get_setting('zone_dir', GENERATED_DIR)
        forward_zone_format = get_setting('forward_zone_format', 'db.{domain}')
        reverse_zone_format = get_setting('reverse_zone_format', 'db.{network}.in-addr.arpa')
        rndc_path = get_setting('rndc_path', '/usr/sbin/rndc')
        checkzone_path = get_setting('checkzone_path', '/usr/sbin/named-checkzone')
        rndc_key = get_setting('rndc_key', '')
        bind_reload_cmd = get_setting('bind_reload_cmd', '')
        reverse_use_reversed_ip = get_setting('reverse_use_reversed_ip', 'false') == 'true'
        return render_template('settings.html', 
            base_domain=base_domain,
            reverse_cidr=reverse_cidr,
            soa_primary=soa_primary,
            soa_admin=soa_admin,
            ttl=ttl,
            ns_records=ns_records,
            forward_root_block=forward_root_block,
            forward_end_block=forward_end_block,
            zone_dir=zone_dir,
            forward_zone_format=forward_zone_format,
            reverse_zone_format=reverse_zone_format,
            reverse_use_reversed_ip=reverse_use_reversed_ip,
            rndc_path=rndc_path,
            checkzone_path=checkzone_path,
            rndc_key=rndc_key,
            bind_reload_cmd=bind_reload_cmd)

    # POST: save settings
    base_domain = request.form.get('base_domain','').strip()
    reverse_cidr = request.form.get('reverse_cidr','').strip()
    soa_primary = request.form.get('soa_primary','').strip()
    soa_admin = request.form.get('soa_admin','').strip()
    forward_root_block = request.form.get('forward_root_block','')
    forward_end_block = request.form.get('forward_end_block','')
    ttl = request.form.get('ttl','3600').strip()
    ns_records = request.form.get('ns_records','').strip()
    zone_dir = request.form.get('zone_dir','').strip() or GENERATED_DIR
    forward_zone_format = request.form.get('forward_zone_format','').strip() or 'db.{domain}'
    reverse_zone_format = request.form.get('reverse_zone_format','').strip() or 'db.{network}.in-addr.arpa'
    # checkbox: present when checked
    reverse_use_reversed_ip = 'true' if request.form.get('reverse_use_reversed_ip') else 'false'
    
    # Get BIND settings
    rndc_path = request.form.get('rndc_path','').strip() or '/usr/sbin/rndc'
    checkzone_path = request.form.get('checkzone_path','').strip() or '/usr/sbin/named-checkzone'
    rndc_key = request.form.get('rndc_key','').strip()
    bind_reload_cmd = request.form.get('bind_reload_cmd','').strip()
    
    if not base_domain:
        return redirect(url_for('settings_ui'))
    
    set_setting('base_domain', base_domain)
    set_setting('reverse_cidr', reverse_cidr)
    set_setting('soa_primary', soa_primary)
    set_setting('soa_admin', soa_admin)
    set_setting('forward_root_block', forward_root_block)
    set_setting('forward_end_block', forward_end_block)
    set_setting('ttl', ttl)
    set_setting('ns_records', ns_records)
    set_setting('zone_dir', zone_dir)
    set_setting('forward_zone_format', forward_zone_format)
    set_setting('reverse_zone_format', reverse_zone_format)
    set_setting('reverse_use_reversed_ip', reverse_use_reversed_ip)
    # Save BIND settings
    set_setting('rndc_path', rndc_path)
    set_setting('checkzone_path', checkzone_path)
    set_setting('rndc_key', rndc_key)
    set_setting('bind_reload_cmd', bind_reload_cmd)
    # regenerate zones
    try:
        generate_all_from_settings()
        return redirect(url_for('index', msg='Settings saved and BIND zones updated'))
    except Exception as e:
        return redirect(url_for('index', msg=f'Settings saved but BIND update failed: {str(e)}'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '80'))
    app.run(host='0.0.0.0', port=port)
