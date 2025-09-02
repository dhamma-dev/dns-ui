#!/usr/bin/env python3
"""
DNS Monitoring Dashboard • v2

Environment variables (recommended):
  APP_PORT=8181
  FETCH_INTERVAL=300       # seconds
  RETENTION_DAYS=30
  SLO_OBJECTIVE=99.9       # percent

Security note: do NOT hardcode secrets; use env vars above.
"""

import os
import json
import sqlite3
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, Response, send_file
from flask_cors import CORS
import threading
import time
from collections import defaultdict
import statistics
import math
import io
import csv
from itertools import combinations
import logging
from logging.handlers import RotatingFileHandler

# --- Config ---
APP_PORT       = int(os.getenv("APP_PORT", "8181"))
FETCH_INTERVAL = int(os.getenv("FETCH_INTERVAL", "300"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
SLO_OBJECTIVE  = float(os.getenv("SLO_OBJECTIVE", "99.9"))

os.makedirs('instance', exist_ok=True)
DB_PATH = "instance/dns_monitoring.db"
CONFIG_PATH = "instance/config.json"

API_BASE_URL, API_TOKEN, ORG_ID = None, None, None

def load_config():
    global API_BASE_URL, API_TOKEN, ORG_ID
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)

            api_token = config.get('api_token')
            org_id = config.get('org_id')
            api_base_url = config.get('api_base_url')

            # All values must exist and the token must not be the placeholder
            if all([api_base_url, api_token, org_id]) and api_token != 'dummy-token':
                API_BASE_URL = api_base_url
                API_TOKEN = api_token
                ORG_ID = org_id
                return True

        except (IOError, json.JSONDecodeError):
            pass  # Fall through to return False

    # If file doesn't exist, is invalid JSON, or fails checks
    API_BASE_URL, API_TOKEN, ORG_ID = None, None, None
    return False

app = Flask(__name__, static_folder=None, template_folder="templates")
CORS(app)

handler = RotatingFileHandler('server.log', maxBytes=100000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# --- DB utilities ---
def connect_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn

class DNSDataCollector:
    def __init__(self):
        self.conn = connect_db()
        self.init_database()
        self.last_insert_ts = 0

    def init_database(self):
        c = self.conn.cursor()
        c.execute('''
        CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            target_domain TEXT,
            dns_server TEXT,
            record_type TEXT,
            response_code TEXT,
            resolution_time INTEGER,
            resolved_ips TEXT,
            appliance_guid TEXT,
            interface TEXT,
            web_path_ids TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_domain ON dns_records(target_domain);')
        c.execute('CREATE INDEX IF NOT EXISTS idx_server ON dns_records(dns_server);')
        c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_records(timestamp);')
        c.execute('CREATE INDEX IF NOT EXISTS idx_appliance ON dns_records(appliance_guid);')
        c.execute('CREATE INDEX IF NOT EXISTS idx_response_code ON dns_records(response_code);')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS uniq_record ON dns_records(timestamp, target_domain, dns_server, record_type);')
        c.execute('''
        CREATE TABLE IF NOT EXISTS saved_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            filters TEXT,
            sort TEXT,
            page_size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')
        self.conn.commit()

    def prune_old(self):
        cutoff = int((datetime.utcnow() - timedelta(days=RETENTION_DAYS)).timestamp() * 1000)
        cur = self.conn.cursor()
        cur.execute("DELETE FROM dns_records WHERE timestamp < ?", (cutoff,))
        self.conn.commit()

    def fetch_and_store_data(self, org_id, start_time, end_time):
        page = 1
        limit = 100
        while True:
            try:
                params = {'orgId': org_id, 'limit': limit, 'page': page}
                if start_time: params['from'] = int(start_time)
                if end_time: params['to'] = int(end_time)
                headers = {'Authorization': API_TOKEN}
                r = requests.get(API_BASE_URL, params=params, headers=headers, timeout=60)
                r.raise_for_status()
                data = r.json()
                if not data: break
                cur = self.conn.cursor()
                for domain_data in data:
                    try:
                        target_domain = domain_data.get('targetDomain', '')
                        appliance_guid = domain_data.get('applianceGuid', '')
                        interface = domain_data.get('interface', '')
                        web_path_ids = json.dumps(domain_data.get('webPathIds', []))
                        for series in domain_data.get('series', []):
                            ts = series.get('timestamp')
                            for record in series.get('data', []):
                                dns_server = record.get('dnsServer', '')
                                for record_type in ['A', 'AAAA', 'CNAME']:
                                    if record_type in record:
                                        rd = record[record_type] or {}
                                        cur.execute('''
                                        INSERT OR IGNORE INTO dns_records
                                        (timestamp, target_domain, dns_server, record_type, response_code, resolution_time,
                                         resolved_ips, appliance_guid, interface, web_path_ids)
                                        VALUES (?,?,?,?,?,?,?,?,?,?)
                                        ''', (ts, target_domain, dns_server, record_type, rd.get('responseCode'), rd.get('resolutionTime'),
                                              json.dumps(rd.get('resolvedIp', [])), appliance_guid, interface, web_path_ids))
                    except (AttributeError, KeyError) as e:
                        app.logger.warning(f"Skipping record due to unexpected structure: {e}")
                        continue
                self.conn.commit()
                if len(data) < limit: break
                page += 1
                time.sleep(1)
            except Exception as e:
                app.logger.error(f"[_fetch_single_range] Error: {e}", exc_info=True)
                return False
        self.last_insert_ts = int(time.time())
        self.prune_old()
        return True

    def get_filtered_data(self, filters, page=1, page_size=100, sort="timestamp:desc", count_only=False):
        c = self.conn.cursor()
        q = "FROM dns_records WHERE 1=1"
        params = []
        if filters.get('domain'): q += " AND target_domain = ?"; params.append(filters['domain'])
        if filters.get('dns_server'): q += " AND dns_server = ?"; params.append(filters['dns_server'])
        if filters.get('response_code'): q += " AND response_code = ?"; params.append(filters['response_code'])
        if filters.get('record_type'): q += " AND record_type = ?"; params.append(filters['record_type'])
        if filters.get('appliance_guid'): q += " AND appliance_guid = ?"; params.append(filters['appliance_guid'])
        if filters.get('q'):
            q += " AND (target_domain LIKE ? OR dns_server LIKE ? OR response_code LIKE ?)"
            needle = f"%{filters['q']}%"
            params.extend([needle, needle, needle])
        if filters.get('start') and filters.get('end'):
            start = int(filters['start'])
            end = int(filters['end'])
            q += " AND timestamp BETWEEN ? AND ?"; params.extend([start, end])
        if count_only:
            c.execute(f"SELECT COUNT(*) AS cnt {q}", params)
            return c.fetchone()['cnt']
        f, d = (sort.split(':') + ['desc'])[:2]
        f = f if f in {'timestamp','target_domain','dns_server','record_type','resolution_time','response_code'} else 'timestamp'
        d = 'ASC' if d.lower()=='asc' else 'DESC'
        order = f"ORDER BY {f} {d}"
        page = max(1, int(page)); page_size = max(1, min(1000, int(page_size)))
        offset = (page-1)*page_size
        c.execute(f"SELECT * {q} {order} LIMIT ? OFFSET ?", params+[page_size, offset])
        rows = [dict(r) for r in c.fetchall()]
        for r in rows:
            r['resolved_ips'] = json.loads(r['resolved_ips']) if r['resolved_ips'] else []
            r['web_path_ids'] = json.loads(r['web_path_ids']) if r['web_path_ids'] else []
        return rows

    def get_statistics(self):
        c = self.conn.cursor()
        stats = {}
        c.execute("SELECT COUNT(DISTINCT target_domain) AS n FROM dns_records")
        stats['total_domains'] = c.fetchone()['n'] or 0
        c.execute("SELECT COUNT(DISTINCT dns_server) AS n FROM dns_records")
        stats['total_dns_servers'] = c.fetchone()['n'] or 0
        c.execute("SELECT COUNT(DISTINCT appliance_guid) AS n FROM dns_records")
        stats['total_appliances'] = c.fetchone()['n'] or 0
        c.execute("SELECT COUNT(*) AS n FROM dns_records")
        stats['total_samples'] = c.fetchone()['n'] or 0
        c.execute("""
          SELECT response_code, COUNT(*) AS c
          FROM dns_records WHERE response_code != 'NOERROR'
          GROUP BY response_code
        """)
        stats['error_counts'] = {row['response_code']: row['c'] for row in c.fetchall()}
        c.execute("""
          SELECT target_domain, dns_server, AVG(resolution_time) AS avg_time
          FROM dns_records WHERE resolution_time > 100
          GROUP BY target_domain, dns_server
          ORDER BY avg_time DESC LIMIT 10
        """)
        stats['slow_queries'] = [dict(r) for r in c.fetchall()]
        c.execute("""
          SELECT target_domain, COUNT(*) AS error_count
          FROM dns_records WHERE response_code != 'NOERROR'
          GROUP BY target_domain ORDER BY error_count DESC LIMIT 10
        """)
        stats['failing_domains'] = [dict(r) for r in c.fetchall()]
        return stats

    def get_comparison_data(self, domain, dns_servers=None):
        c = self.conn.cursor()
        params = [domain]
        sub = ""
        if dns_servers:
            sub = " AND dns_server IN ({})".format(",".join("?"*len(dns_servers)))
            params += dns_servers
        c.execute(f"""
          SELECT dns_server, record_type,
                 AVG(resolution_time) AS avg_time,
                 MIN(resolution_time) AS min_time,
                 MAX(resolution_time) AS max_time,
                 COUNT(*) AS sample_count,
                 SUM(CASE WHEN response_code != 'NOERROR' THEN 1 ELSE 0 END) AS error_count
          FROM dns_records
          WHERE target_domain = ? {sub}
          GROUP BY dns_server, record_type
        """, params)
        rows = [dict(r) for r in c.fetchall()]
        for r in rows:
            c.execute("""
              SELECT resolution_time AS rt FROM dns_records
              WHERE target_domain=? AND dns_server=? AND record_type=?
            """, (domain, r['dns_server'], r['record_type']))
            vals = [x['rt'] for x in c.fetchall() if x['rt'] is not None]
            r['p95'] = percentile(vals, 95) if vals else None
        return rows

    def domain_summary(self, domain, start_ts, end_ts):
        c = self.conn.cursor()
        c.execute("""
          SELECT resolution_time AS rt, response_code AS code, dns_server AS srv, timestamp AS ts
          FROM dns_records WHERE target_domain=? AND timestamp BETWEEN ? AND ?
          ORDER BY timestamp ASC
        """, (domain, start_ts, end_ts))
        rows = [dict(r) for r in c.fetchall()]
        vals = [r['rt'] for r in rows if r['rt'] is not None]
        errors = sum(1 for r in rows if r['code']!='NOERROR')
        samples = len(rows)
        servers = sorted({r['srv'] for r in rows})
        ts_bucket = bucket_by_hour(rows)
        timeseries = []
        for ts, group in ts_bucket.items():
            arr = [g['rt'] for g in group if g['rt'] is not None]
            if not arr: 
                avg = p95 = 0
            else:
                avg = sum(arr)/len(arr)
                p95 = percentile(arr, 95)
            e = sum(1 for g in group if g['code']!='NOERROR')
            er = (e/len(group)*100) if group else 0
            timeseries.append({"ts": ts, "avg": avg, "p95": p95, "err_rate": er})
        breakdown = []
        for s in servers:
            arr = [r['rt'] for r in rows if r['srv']==s and r['rt'] is not None]
            if not arr: continue
            breakdown.append({
                "dns_server": s,
                "avg": sum(arr)/len(arr),
                "p95": percentile(arr,95),
                "errors": sum(1 for r in rows if r['srv']==s and r['code']!='NOERROR'),
                "count": sum(1 for r in rows if r['srv']==s),
            })
        return {
            "samples": samples,
            "error_rate": (errors/samples*100) if samples else 0.0,
            "p50": percentile(vals, 50) if vals else 0,
            "p95": percentile(vals, 95) if vals else 0,
            "p99": percentile(vals, 99) if vals else 0,
            "servers": servers,
            "server_breakdown": breakdown,
            "timeseries": timeseries,
        }

    def anomalies(self, hours=24):
        c = self.conn.cursor()
        end = int(datetime.utcnow().timestamp()*1000)
        start = end - hours*3600*1000
        c.execute("""
          SELECT target_domain AS d, dns_server AS s, resolution_time AS rt
          FROM dns_records WHERE timestamp BETWEEN ? AND ? AND resolution_time IS NOT NULL
        """, (start, end))
        rows = [dict(r) for r in c.fetchall()]
        by_pair = defaultdict(list)
        for r in rows: by_pair[(r['d'], r['s'])].append(r['rt'])
        out = []
        for (d,s), arr in by_pair.items():
            if len(arr) < 20: continue
            mu = statistics.mean(arr)
            sd = statistics.pstdev(arr) or 1.0
            for v in arr[-5:]:
                z = (v - mu)/sd
                if z > 3.0:
                    out.append({"target_domain": d, "dns_server": s, "value": v, "z": z})
        out.sort(key=lambda x: x['z'], reverse=True)
        return out[:20]

    def servers_summary(self, hours=24):
        c = self.conn.cursor()
        end = int(datetime.utcnow().timestamp()*1000)
        start = end - hours*3600*1000
        c.execute("""
          SELECT dns_server AS s, resolution_time AS rt, response_code AS code, timestamp AS ts
          FROM dns_records
          WHERE timestamp BETWEEN ? AND ?
        """, (start, end))
        rows = [dict(r) for r in c.fetchall()]
        by_srv = defaultdict(list)
        for r in rows:
            by_srv[r['s']].append(r)
        out = []
        for s, arr in by_srv.items():
            rts = [x['rt'] for x in arr if x['rt'] is not None]
            samples = len(arr)
            errors = sum(1 for x in arr if x['code'] != 'NOERROR')
            tsb = bucket_by_hour([{'ts': x['ts'], 'rt': x['rt'], 'code': x['code']} for x in arr])
            timeseries = []
            for ts, g in sorted(tsb.items(), key=lambda kv: kv[0]):
                g_rt = [v['rt'] for v in g if v['rt'] is not None]
                er = (sum(1 for v in g if v['code']!='NOERROR')/len(g)*100) if g else 0
                timeseries.append({'ts': ts, 'avg': (sum(g_rt)/len(g_rt) if g_rt else 0), 'p95': percentile(g_rt,95) if g_rt else 0, 'err': er})
            out.append({
                'dns_server': s,
                'samples': samples,
                'errors': errors,
                'error_rate': (errors/samples*100) if samples else 0,
                'avg': (sum(rts)/len(rts)) if rts else 0,
                'p95': percentile(rts, 95) if rts else 0,
                'p99': percentile(rts, 99) if rts else 0,
                'timeseries': timeseries[-24:]
            })
        out.sort(key=lambda x: (x['p95'] or 0, x['error_rate']), reverse=True)
        return out

    def consistency(self, domain, hours=24, record_type=None, servers=None):
        c = self.conn.cursor()
        end = int(datetime.utcnow().timestamp()*1000)
        start = end - hours*3600*1000
        sql = """
          SELECT dns_server AS s, response_code AS code, resolved_ips, record_type
          FROM dns_records
          WHERE target_domain=? AND timestamp BETWEEN ? AND ?
        """
        params = [domain, start, end]
        if record_type:
            sql += " AND record_type=?"
            params.append(record_type)
        if servers:
            sql += f" AND dns_server IN ({','.join('?'*len(servers))})"
            params.extend(servers)
        c.execute(sql, params)
        rows = [dict(r) for r in c.fetchall()]
        by_srv = {}
        for r in rows:
            if r['code'] != 'NOERROR': 
                continue
            ips = []
            try:
                ips = json.loads(r['resolved_ips']) if r['resolved_ips'] else []
            except Exception:
                pass
            if ips:
                by_srv.setdefault(r['s'], set()).update(ips)
        servers_list = sorted(by_srv.keys())
        pairs = []
        for a,b in combinations(servers_list, 2):
            A, B = by_srv.get(a,set()), by_srv.get(b,set())
            inter = len(A & B); uni = len(A | B) or 1
            score = inter/uni
            pairs.append({'a': a, 'b': b, 'jaccard': score, 'overlap': inter, 'union': uni})
        overall = (sum(p['jaccard'] for p in pairs)/len(pairs)) if pairs else 0.0
        ref_srv = max(servers_list, key=lambda s: len(by_srv.get(s,set())), default=None)
        ref_set = by_srv.get(ref_srv, set())
        mismatches = []
        for s in servers_list:
            if by_srv[s] != ref_set:
                mismatches.append({
                    'dns_server': s,
                    'missing': sorted(list(ref_set - by_srv[s])),
                    'extra': sorted(list(by_srv[s] - ref_set))
                })
        return {
            'domain': domain,
            'record_type': record_type,
            'hours': hours,
            'servers': servers_list,
            'overall_consistency': overall,
            'pairs': pairs,
            'reference_server': ref_srv,
            'reference_ips': sorted(list(ref_set)),
            'by_server_ips': {s: sorted(list(by_srv[s])) for s in servers_list},
            'mismatches': mismatches
        }

    def time_compare(self, domain=None, dns_server=None, record_type=None, hours_a=1, hours_b=1, offset_b=None):
        endA = int(datetime.utcnow().timestamp()*1000)
        startA = endA - hours_a*3600*1000
        if offset_b is None:
            offset_b = hours_b
        endB = startA - offset_b*3600*1000
        startB = endB - hours_b*3600*1000
        def query_window(st, en):
            c = self.conn.cursor()
            q = "SELECT resolution_time AS rt, response_code AS code, timestamp AS ts FROM dns_records WHERE timestamp BETWEEN ? AND ?"
            params = [st,en]
            if domain: q += " AND target_domain=?"; params.append(domain)
            if dns_server: q += " AND dns_server=?"; params.append(dns_server)
            if record_type: q += " AND record_type=?"; params.append(record_type)
            c.execute(q, params)
            rows = [dict(r) for r in c.fetchall()]
            rts = [x['rt'] for x in rows if x['rt'] is not None]
            samples = len(rows)
            errors = sum(1 for x in rows if x['code']!='NOERROR')
            tsb = bucket_by_hour([{'ts': x['ts'], 'rt': x['rt'], 'code': x['code']} for x in rows])
            ts = []
            for tskey, g in sorted(tsb.items(), key=lambda kv: kv[0]):
                g_rt = [v['rt'] for v in g if v['rt'] is not None]
                ts.append({'ts': tskey, 'avg': (sum(g_rt)/len(g_rt) if g_rt else 0), 'p95': percentile(g_rt,95) if g_rt else 0,
                           'err': (sum(1 for v in g if v['code']!='NOERROR')/len(g)*100) if g else 0})
            return {
                'samples': samples,
                'errors': errors,
                'error_rate': (errors/samples*100) if samples else 0,
                'avg': (sum(rts)/len(rts)) if rts else 0,
                'p95': percentile(rts,95) if rts else 0,
                'p99': percentile(rts,99) if rts else 0,
                'timeseries': ts
            }
        return {
            'windowA': {'start': startA, 'end': endA, **query_window(startA, endA)},
            'windowB': {'start': startB, 'end': endB, **query_window(startB, endB)}
        }

    def points_summary(self, hours=24):
        c = self.conn.cursor()
        end = int(datetime.utcnow().timestamp()*1000)
        start = end - hours*3600*1000
        c.execute("""
          SELECT appliance_guid AS ag, interface AS iface,
                 resolution_time AS rt, response_code AS code, timestamp AS ts
          FROM dns_records
          WHERE timestamp BETWEEN ? AND ?
        """, (start, end))
        rows = [dict(r) for r in c.fetchall()]
        by_point = defaultdict(list)
        for r in rows:
            key = (r['ag'] or '—', r['iface'] or '—')
            by_point[key].append(r)
        out = []
        for (ag, iface), arr in by_point.items():
            rts = [x['rt'] for x in arr if x['rt'] is not None]
            samples = len(arr)
            errors = sum(1 for x in arr if x['code'] != 'NOERROR')
            tsb = bucket_by_hour([{'ts': x['ts'], 'rt': x['rt'], 'code': x['code']} for x in arr])
            timeseries = []
            for ts, g in sorted(tsb.items(), key=lambda kv: kv[0]):
                g_rt = [v['rt'] for v in g if v['rt'] is not None]
                er = (sum(1 for v in g if v['code']!='NOERROR')/len(g)*100) if g else 0
                timeseries.append({'ts': ts, 'avg': (sum(g_rt)/len(g_rt) if g_rt else 0),
                                   'p95': percentile(g_rt,95) if g_rt else 0, 'err': er})
            out.append({
                'appliance_guid': ag, 'interface': iface,
                'point_id': f"{ag}::{iface}",
                'samples': samples, 'errors': errors,
                'error_rate': (errors/samples*100) if samples else 0,
                'avg': (sum(rts)/len(rts)) if rts else 0,
                'p95': percentile(rts, 95) if rts else 0,
                'p99': percentile(rts, 99) if rts else 0,
                'timeseries': timeseries[-24:]
            })
        out.sort(key=lambda x: (x['p95'] or 0, x['error_rate']), reverse=True)
        return out

    def point_detail(self, appliance_guid, hours=24, interface=None):
        c = self.conn.cursor()
        end = int(datetime.utcnow().timestamp()*1000)
        start = end - hours*3600*1000
        q = """
          SELECT target_domain AS d, dns_server AS s, record_type AS t,
                 resolution_time AS rt, response_code AS code, timestamp AS ts
          FROM dns_records
          WHERE appliance_guid=? AND timestamp BETWEEN ? AND ?
        """
        params = [appliance_guid, start, end]
        if interface:
            q += " AND interface=?"; params.append(interface)
        c.execute(q, params)
        rows = [dict(r) for r in c.fetchall()]
        tsb = bucket_by_hour([{'ts': r['ts'], 'rt': r['rt'], 'code': r['code']} for r in rows])
        timeseries = []
        all_rts = [r['rt'] for r in rows if r['rt'] is not None]
        errs = sum(1 for r in rows if r['code']!='NOERROR')
        for ts, grp in sorted(tsb.items(), key=lambda kv: kv[0]):
            gr = [g['rt'] for g in grp if g['rt'] is not None]
            timeseries.append({
                'ts': ts,
                'avg': (sum(gr)/len(gr) if gr else 0),
                'p95': percentile(gr,95) if gr else 0,
                'err': (sum(1 for g in grp if g['code']!='NOERROR')/len(grp)*100) if grp else 0
            })
        by_dom = defaultdict(list)
        for r in rows:
            by_dom[r['d']].append(r)
        domains = []
        for d, arr in by_dom.items():
            rts = [x['rt'] for x in arr if x['rt'] is not None]
            domains.append({
                'domain': d,
                'count': len(arr),
                'avg': (sum(rts)/len(rts)) if rts else 0,
                'p95': percentile(rts,95) if rts else 0,
                'errors': sum(1 for x in arr if x['code']!='NOERROR'),
                'error_rate': (sum(1 for x in arr if x['code']!='NOERROR')/len(arr)*100)
            })
        domains.sort(key=lambda x: (x['p95'], x['error_rate'], x['count']), reverse=True)
        top_domains = domains[:12]
        by_srv = defaultdict(list)
        for r in rows:
            by_srv[r['s']].append(r)
        servers = []
        for s, arr in by_srv.items():
            rts = [x['rt'] for x in arr if x['rt'] is not None]
            servers.append({
                'dns_server': s,
                'count': len(arr),
                'avg': (sum(rts)/len(rts)) if rts else 0,
                'p95': percentile(rts,95) if rts else 0,
                'errors': sum(1 for x in arr if x['code']!='NOERROR'),
                'error_rate': (sum(1 for x in arr if x['code']!='NOERROR')/len(arr)*100)
            })
        servers.sort(key=lambda x: (x['p95'], x['error_rate'], x['count']), reverse=True)
        types = defaultdict(lambda: {'count':0,'errors':0})
        for r in rows:
            types[r['t']]['count'] += 1
            if r['code']!='NOERROR': types[r['t']]['errors'] += 1
        record_types = [{'type':k,'count':v['count'],
                         'error_rate': (v['errors']/v['count']*100) if v['count'] else 0}
                        for k,v in types.items()]
        heatmap = []
        ordered_hours = sorted(tsb.keys())
        for ts in ordered_hours:
            row = {'ts': ts, 'cells': []}
            for d in [x['domain'] for x in top_domains]:
                vals = [r['rt'] for r in by_dom[d] if r['ts']//3600000 == ts//3600000 and r['rt'] is not None]
                row['cells'].append(percentile(vals,95) if vals else 0)
            heatmap.append(row)
        return {
            'appliance_guid': appliance_guid,
            'interface': interface,
            'samples': len(rows),
            'error_rate': (errs/len(rows)*100) if rows else 0,
            'avg': (sum(all_rts)/len(all_rts)) if all_rts else 0,
            'p95': percentile(all_rts,95) if all_rts else 0,
            'p99': percentile(all_rts,99) if all_rts else 0,
            'timeseries': timeseries,
            'top_domains': top_domains,
            'servers': servers[:12],
            'record_types': record_types,
            'heatmap': {'domains': [x['domain'] for x in top_domains], 'rows': heatmap}
        }

    def point_compare(self, a_guid, b_guid, hours=24, a_iface=None, b_iface=None):
        A = self.point_detail(a_guid, hours, a_iface)
        B = self.point_detail(b_guid, hours, b_iface)
        def slim(x):
            return {'samples': x['samples'], 'error_rate': x['error_rate'],
                    'avg': x['avg'], 'p95': x['p95'], 'p99': x['p99']}
        return {'A': slim(A), 'B': slim(B)}

def bucket_by_hour(rows):
    buckets = defaultdict(list)
    for r in rows:
        ts = r['ts']
        dt = datetime.utcfromtimestamp(ts/1000).replace(minute=0, second=0, microsecond=0)
        buckets[int(dt.timestamp()*1000)].append(r)
    return buckets

def percentile(arr, p):
    if not arr: return 0
    arr = sorted(arr)
    k = (len(arr)-1) * (p/100)
    f = math.floor(k); c = math.ceil(k)
    if f == c: return arr[int(k)]
    return arr[f] + (arr[c]-arr[f])*(k-f)

collector = DNSDataCollector()

@app.route('/api/status')
def api_status():
    return jsonify({'configured': all([API_TOKEN, ORG_ID, API_BASE_URL])})

@app.route('/api/config', methods=['POST'])
def api_config():
    data = request.get_json()
    if not data or not all(k in data for k in ['api_base_url', 'api_token', 'org_id']):
        return jsonify({'error': 'Missing required fields'}), 400
    app.logger.info(f"Writing config to {CONFIG_PATH}: {data}")
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(data, f)
        app.logger.info("Config file written successfully.")
        load_config()
    except Exception as e:
        app.logger.error(f"Failed to write config file: {e}")
        return jsonify({'error': 'Failed to write config file'}), 500
    return jsonify({'ok': True})

@app.route('/api/fetch_data', methods=['POST'])
def api_fetch_data():
    if not all([API_TOKEN, ORG_ID, API_BASE_URL]):
        return jsonify({'error': 'Application not configured'}), 400
    data = request.get_json()
    start_time = data.get('start')
    end_time = data.get('end')
    if not start_time or not end_time:
        return jsonify({'error': 'start and end time parameters are required'}), 400

    collector.fetch_and_store_data(ORG_ID, start_time, end_time)
    return jsonify({'ok': True, 'message': 'Data fetch initiated.'})

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/data')
def get_data():
    filters = {
        'q': request.args.get('q'),
        'domain': request.args.get('domain'),
        'dns_server': request.args.get('dns_server'),
        'response_code': request.args.get('response_code'),
        'record_type': request.args.get('record_type'),
        'appliance_guid': request.args.get('appliance_guid')
    }
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 100, type=int)
    sort = request.args.get('sort', 'timestamp:desc')
    if request.args.get('start') and request.args.get('end'):
        filters['start'] = request.args.get('start')
        filters['end'] = request.args.get('end')
    else:
        filters['time_range'] = request.args.get('time_range', '24')
    total = collector.get_filtered_data(filters, count_only=True, page=1, page_size=1, sort=sort)
    rows = collector.get_filtered_data(filters, page=page, page_size=page_size, sort=sort)
    return jsonify({"total": total, "rows": rows})

@app.route('/api/statistics')
def api_statistics():
    return jsonify(collector.get_statistics())

@app.route('/api/domains')
def api_domains():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT target_domain FROM dns_records ORDER BY target_domain")
    data = [r[0] for r in cur.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/dns_servers')
def api_dns_servers():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT dns_server FROM dns_records ORDER BY dns_server")
    data = [r[0] for r in cur.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/appliances')
def api_appliances():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT appliance_guid FROM dns_records WHERE appliance_guid != '' ORDER BY appliance_guid")
    data = [r[0] for r in cur.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/compare')
def api_compare():
    domain = request.args.get('domain')
    servers = request.args.getlist('servers[]')
    if not domain:
        return jsonify({'error':'domain required'}), 400
    return jsonify(collector.get_comparison_data(domain, servers if servers else None))

@app.route('/api/domain_summary')
def api_domain_summary():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({'error':'domain required'}), 400
    start_time = request.args.get('start', type=int)
    end_time = request.args.get('end', type=int)
    if not start_time or not end_time:
        hours = request.args.get('hours', 24, type=int)
        end_time = int(datetime.utcnow().timestamp() * 1000)
        start_time = end_time - hours * 3600 * 1000
    return jsonify(collector.domain_summary(domain, start_time, end_time))

@app.route('/api/anomalies')
def api_anomalies():
    hours = request.args.get('hours', 24, type=int)
    return jsonify(collector.anomalies(hours))

@app.route('/api/export')
def api_export():
    filters = {
        'q': request.args.get('q'),
        'domain': request.args.get('domain'),
        'dns_server': request.args.get('dns_server'),
        'response_code': request.args.get('response_code'),
        'record_type': request.args.get('record_type'),
        'appliance_guid': request.args.get('appliance_guid'),
        'time_range': request.args.get('time_range', '24')
    }
    sort = request.args.get('sort', 'timestamp:desc')
    limit = min(int(request.args.get('limit', 5000)), 50000)
    rows = collector.get_filtered_data(filters, page=1, page_size=limit, sort=sort)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp","target_domain","dns_server","record_type","response_code","resolution_time","resolved_ips","appliance_guid","interface"])
    for r in rows:
        writer.writerow([
            r['timestamp'], r['target_domain'], r['dns_server'], r['record_type'], r['response_code'],
            r['resolution_time'], ",".join(r['resolved_ips']), r.get('appliance_guid',''), r.get('interface','')
        ])
    mem = io.BytesIO(buf.getvalue().encode('utf-8'))
    mem.seek(0)
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name='dns_export.csv')

@app.route('/api/saved_views', methods=['GET','POST'])
def api_saved_views():
    conn = connect_db(); cur = conn.cursor()
    if request.method == 'POST':
        body = request.get_json(force=True)
        name = body.get('name'); 
        if not name: return jsonify({'error':'name required'}), 400
        filters = json.dumps(body.get('filters', {}))
        sort = json.dumps(body.get('sort', 'timestamp:desc'))
        page_size = int(body.get('pageSize', 100))
        try:
            cur.execute("INSERT INTO saved_views(name,filters,sort,page_size) VALUES (?,?,?,?)",
                        (name, filters, sort, page_size))
            conn.commit()
            return jsonify({'ok':True})
        except sqlite3.IntegrityError:
            return jsonify({'error':'name must be unique'}), 400
    else:
        cur.execute("SELECT name, filters, sort, page_size, created_at FROM saved_views ORDER BY name")
        data = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(data)

@app.route('/api/saved_views/<name>')
def api_saved_view(name):
    conn = connect_db(); cur = conn.cursor()
    cur.execute("SELECT name, filters, sort, page_size FROM saved_views WHERE name=?", (name,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    out = dict(row)
    out['filters'] = json.loads(out['filters'])
    out['sort'] = json.loads(out['sort']) if isinstance(out['sort'], str) else out['sort']
    conn.close()
    return jsonify(out)

@app.route('/api/servers_summary')
def api_servers_summary():
    hours = request.args.get('hours', 24, type=int)
    return jsonify(collector.servers_summary(hours))

@app.route('/api/consistency')
def api_consistency():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({'error':'domain required'}), 400
    hours = request.args.get('hours', 24, type=int)
    record_type = request.args.get('record_type')
    servers = request.args.getlist('servers[]') or None
    return jsonify(collector.consistency(domain, hours, record_type, servers))

@app.route('/api/time_compare')
def api_time_compare():
    domain = request.args.get('domain')
    dns_server = request.args.get('dns_server')
    record_type = request.args.get('record_type')
    ha = request.args.get('hours_a', 1, type=int)
    hb = request.args.get('hours_b', 1, type=int)
    ob = request.args.get('offset_b', None, type=int)
    return jsonify(collector.time_compare(domain, dns_server, record_type, ha, hb, ob))

@app.route('/servers')
def page_servers():
    return render_template('servers.html')

@app.route('/consistency')
def page_consistency():
    return render_template('consistency.html')

@app.route('/time-compare')
def page_time_compare():
    return render_template('time_compare.html')

@app.route('/api/points_summary')
def api_points_summary():
    hours = request.args.get('hours', 24, type=int)
    return jsonify(collector.points_summary(hours))

@app.route('/api/point_detail')
def api_point_detail():
    ag = request.args.get('appliance_guid')
    if not ag: return jsonify({'error':'appliance_guid required'}), 400
    hours = request.args.get('hours', 24, type=int)
    iface = request.args.get('interface')
    return jsonify(collector.point_detail(ag, hours, iface))

@app.route('/api/point_compare')
def api_point_compare():
    a = request.args.get('a'); b = request.args.get('b')
    if not a or not b: return jsonify({'error':'a and b required'}), 400
    hours = request.args.get('hours', 24, type=int)
    ai = request.args.get('a_iface'); bi = request.args.get('b_iface')
    return jsonify(collector.point_compare(a, b, hours, ai, bi))

@app.route('/points')
def page_points():
    return render_template('points.html')

@app.route('/api/stream')
def stream():
    def gen():
        last_ping = 0
        while True:
            time.sleep(10)
            now = int(time.time())
            if collector.last_insert_ts > last_ping or now % 30 == 0:
                last_ping = collector.last_insert_ts
                yield "data: tick\n\n"
    return Response(gen(), mimetype='text/event-stream')

if __name__ == '__main__':
    os.makedirs('instance', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    if not os.path.exists(os.path.join('templates','dashboard.html')):
        with open(os.path.join('templates','dashboard.html'), 'w', encoding='utf-8') as f:
            f.write('<h2>Place dashboard.html here</h2>')
    if load_config():
        app.logger.info("Configuration loaded from file.")
    else:
        app.logger.info("Waiting for configuration via web UI...")
    print(f"Starting DNS Dashboard v2 on http://0.0.0.0:{APP_PORT}")
    app.run(debug=True, host='0.0.0.0', port=APP_PORT, use_reloader=True)
