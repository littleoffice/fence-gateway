#!/usr/bin/env python3
"""Draw the diagrams in this directory: the three relay credential modes, and
one tool call in exchange mode. Each is written in a light and a dark variant;
the docs embed both with <picture>, so GitHub shows the one matching the
reader's theme.

    python3 docs/diagrams/render.py

Standard library only. Edit the shapes below and run it again.
"""
import os
import re

def marker(pid, cls):
    return f'<marker id="{pid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="{cls}"/></marker>'

def panel(mode):
    p = mode
    defs = "<defs>" + marker(f"a-{p}", "mk-ink") + marker(f"w-{p}", "mk-warn") + marker(f"x-{p}", "mk-idp") + "</defs>"
    s = [f'<svg viewBox="0 0 340 332" role="img" aria-label="{ARIA[p]}">', defs]
    # people
    s += ['<rect x="30" y="16" width="110" height="38" rx="6" class="box"/>',
          '<text x="85" y="40" class="t lbl" text-anchor="middle">Alice</text>',
          '<rect x="200" y="16" width="110" height="38" rx="6" class="box"/>',
          '<text x="255" y="40" class="t lbl" text-anchor="middle">Bob</text>']
    s += [f'<line x1="85" y1="54" x2="138" y2="126" class="ln" marker-end="url(#a-{p})"/>',
          f'<line x1="255" y1="54" x2="202" y2="126" class="ln" marker-end="url(#a-{p})"/>',
          '<text x="104" y="96" class="m tok" text-anchor="end">alice-token</text>',
          '<text x="236" y="96" class="m tok" text-anchor="start">bob-token</text>']
    # gateway
    s += ['<rect x="95" y="130" width="150" height="46" rx="6" class="box gw"/>',
          '<text x="170" y="158" class="t lbl" text-anchor="middle">gateway</text>']
    # relay
    s += ['<rect x="95" y="258" width="150" height="46" rx="6" class="box"/>',
          '<text x="170" y="286" class="t lbl" text-anchor="middle">relay</text>']
    s += [f'<line x1="170" y1="176" x2="170" y2="254" class="ln" marker-end="url(#a-{p})"/>']
    lines = DOWN[p]
    for i, l in enumerate(lines):
        s.append(f'<text x="180" y="{212 + i*15}" class="m tok" text-anchor="start">{l}</text>')
    if p == "exchange":
        s += ['<rect x="262" y="130" width="70" height="46" rx="6" class="box idp"/>',
              '<text x="297" y="158" class="t lbl" text-anchor="middle">IdP</text>',
              f'<line x1="245" y1="145" x2="258" y2="145" class="ln idpln" marker-end="url(#x-{p})"/>',
              f'<line x1="262" y1="162" x2="249" y2="162" class="ln idpln" marker-end="url(#x-{p})"/>',
              '<text x="297" y="194" class="m tok" text-anchor="middle">swap</text>']
    # side door
    if p == "passthrough":
        s += [f'<path d="M30,35 H14 V281 H91" class="door open" marker-end="url(#w-{p})"/>',
              '<text x="18" y="324" class="m door-t open-t">side door: open</text>']
    else:
        s += ['<path d="M30,35 H14 V281 H60" class="door shut"/>',
              '<circle cx="70" cy="281" r="9" class="stop"/>',
              '<path d="M65,276 L75,286 M75,276 L65,286" class="stop-x"/>',
              '<text x="18" y="324" class="m door-t shut-t">side door: blocked</text>']
    s.append('</svg>')
    return "\n".join(s)

ARIA = {
 "static": "Static mode: Alice and Bob send their own tokens to the gateway; the gateway calls the relay with its own token, so the relay sees one caller. Alice's token does not work at the relay.",
 "passthrough": "Passthrough mode: the gateway forwards Alice's and Bob's own tokens to the relay, so the relay sees each of them. Their tokens also work at the relay directly, so the side door is open.",
 "exchange": "Exchange mode: the gateway swaps each caller's token at the identity provider for a relay token for the same user. The relay sees each caller, and a caller's own token does not work at the relay.",
}
DOWN = {
 "static": ["gateway's token"],
 "passthrough": ["alice-token", "or bob-token"],
 "exchange": ["relay token", "for alice / bob"],
}

flow = '''<svg viewBox="0 0 960 470" role="img" aria-label="Full exchange setup. The MCP client logs in at the identity provider and calls the gateway with its user token. The gateway checks it, swaps it at the identity provider for a relay token, and calls the relay with that. The relay, reachable only from the gateway, searches through SearXNG and returns signed fences, which the gateway verifies before answering the client. A direct call from the client to the relay is blocked by the network and by the token audience.">
<defs>MARKERS</defs>
<!-- identity provider -->
<rect x="300" y="24" width="250" height="120" rx="8" class="box idp"/>
<text x="425" y="50" class="t lbl" text-anchor="middle">Identity provider</text>
<text x="425" y="68" class="m sub" text-anchor="middle">authentik · Keycloak</text>
<rect x="316" y="86" width="104" height="38" rx="6" class="pill"/>
<text x="368" y="104" class="m pill-t" text-anchor="middle">client G</text>
<text x="368" y="118" class="m pill-s" text-anchor="middle">user tokens</text>
<rect x="430" y="86" width="104" height="38" rx="6" class="pill"/>
<text x="482" y="104" class="m pill-t" text-anchor="middle">client R</text>
<text x="482" y="118" class="m pill-s" text-anchor="middle">relay tokens</text>
<!-- client -->
<rect x="20" y="250" width="160" height="64" rx="8" class="box"/>
<text x="100" y="278" class="t lbl" text-anchor="middle">MCP client</text>
<text x="100" y="297" class="m sub" text-anchor="middle">Claude · Cursor</text>
<!-- gateway -->
<rect x="310" y="250" width="190" height="64" rx="8" class="box gw"/>
<text x="405" y="278" class="t lbl" text-anchor="middle">fence-gateway</text>
<text x="405" y="297" class="m sub" text-anchor="middle">AUTH_MODE=exchange</text>
<!-- boundary -->
<rect x="600" y="200" width="344" height="164" rx="10" class="zone"/>
<text x="614" y="222" class="m zone-t">relay network · only the gateway may enter</text>
<rect x="616" y="250" width="150" height="64" rx="8" class="box"/>
<text x="691" y="278" class="t lbl" text-anchor="middle">relay</text>
<text x="691" y="297" class="m sub" text-anchor="middle">signs fences</text>
<rect x="800" y="250" width="128" height="64" rx="8" class="box"/>
<text x="864" y="286" class="t lbl" text-anchor="middle">SearXNG</text>
<!-- web -->
<rect x="800" y="404" width="128" height="44" rx="8" class="box"/>
<text x="864" y="431" class="t lbl" text-anchor="middle">the web</text>
<line x1="864" y1="314" x2="864" y2="400" class="ln" marker-end="url(#fa)"/>
<text x="856" y="382" class="m tok" text-anchor="end">search · fetch</text>
<line x1="766" y1="282" x2="796" y2="282" class="ln" marker-end="url(#fa)"/>

<!-- 1 login -->
<path d="M100,250 V105 H312" class="ln idpln" marker-end="url(#fi)"/>
<text x="112" y="96" class="m tok">user token · aud G</text>
<!-- 2 call gateway -->
<line x1="180" y1="272" x2="306" y2="272" class="ln" marker-end="url(#fa)"/>
<text x="248" y="264" class="m tok" text-anchor="middle">user token</text>
<!-- 3/4 exchange -->
<line x1="390" y1="250" x2="390" y2="148" class="ln idpln" marker-end="url(#fi)"/>
<line x1="450" y1="148" x2="450" y2="246" class="ln idpln" marker-end="url(#fi)"/>
<text x="380" y="200" class="m tok" text-anchor="end">user token</text>
<text x="460" y="200" class="m tok">relay token</text>
<text x="460" y="214" class="m tok">sub alice · aud R</text>
<!-- 5 call relay -->
<line x1="500" y1="272" x2="612" y2="272" class="ln acc" marker-end="url(#fg)"/>
<text x="561" y="264" class="m tok" text-anchor="middle">relay token</text>
<!-- 6 back -->
<line x1="616" y1="300" x2="504" y2="300" class="ln" marker-end="url(#fa)"/>
<text x="550" y="324" class="m tok" text-anchor="middle">signed fences</text>
<!-- 7 answer -->
<line x1="310" y1="300" x2="184" y2="300" class="ln acc" marker-end="url(#fg)"/>
<text x="240" y="324" class="m tok" text-anchor="middle">verified result</text>
<!-- side door -->
<path d="M100,314 V420 H660 V384" class="door shut"/>
<circle cx="660" cy="374" r="10" class="stop"/>
<path d="M654.5,368.5 L665.5,379.5 M665.5,368.5 L654.5,379.5" class="stop-x"/>
<text x="112" y="440" class="m door-t shut-t">direct call with the user token: stopped by the network, and refused by the relay (wrong audience)</text>

<!-- step numbers -->
STEPS
</svg>'''
markers = marker("fa","mk-ink") + marker("fi","mk-idp") + marker("fg","mk-acc")
steps = [(1,100,180),(2,200,272),(3,390,226),(4,450,170),(5,512,272),(6,600,300),(7,292,300)]
st = "\n".join(f'<circle cx="{x}" cy="{y}" r="11" class="num"/><text x="{x}" y="{y+4}" class="num-t" text-anchor="middle">{n}</text>' for n,x,y in steps)
flow = flow.replace("MARKERS", markers).replace("STEPS", st)


THEMES = {
 "light": dict(paper="#f3f5f7", surface="#ffffff", ink="#17212b", muted="#5b6875", line="#c3ccd5",
               accent="#0b6b78", accent_soft="#e2f1f3", idp="#9a5b07", idp_soft="#fbf0df",
               warn="#b42318", ok="#2e7a4c", zone="#eef2f5"),
 "dark":  dict(paper="#0f151a", surface="#172028", ink="#e4eaef", muted="#98a6b3", line="#37454f",
               accent="#56b8c4", accent_soft="#15333a", idp="#e3a653", idp_soft="#33260f",
               warn="#f0776d", ok="#6cc38e", zone="#131b21"),
}
SANS = "'IBM Plex Sans','Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif"
MONO = "'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

def css(c):
    return f"""
.bg{{fill:{c['surface']}}}
.box{{fill:{c['surface']};stroke:{c['line']};stroke-width:1.5}}
.box.gw{{stroke:{c['accent']};stroke-width:2;fill:{c['accent_soft']}}}
.box.idp{{stroke:{c['idp']};fill:{c['idp_soft']}}}
.pill{{fill:{c['surface']};stroke:{c['idp']};stroke-width:1.2}}
.zone{{fill:{c['zone']};stroke:{c['muted']};stroke-width:1.2;stroke-dasharray:6 5}}
.t{{fill:{c['ink']};font-family:{SANS}}}
.lbl{{font-size:14px;font-weight:600}}
.m{{font-family:{MONO}}}
.sub,.tok,.zone-t{{fill:{c['muted']};font-size:11px}}
.pill-t{{fill:{c['ink']};font-size:11px;font-weight:500}}
.pill-s{{fill:{c['muted']};font-size:10px}}
.head{{fill:{c['ink']};font-family:{MONO};font-size:16px;font-weight:600}}
.head-s{{fill:{c['muted']};font-family:{MONO};font-size:11px}}
.head-s.rec{{fill:{c['accent']}}}
.ln{{stroke:{c['ink']};stroke-width:1.5;fill:none}}
.ln.acc{{stroke:{c['accent']};stroke-width:2}}
.idpln{{stroke:{c['idp']}}}
.mk-ink{{fill:{c['ink']}}}.mk-idp{{fill:{c['idp']}}}.mk-acc{{fill:{c['accent']}}}.mk-warn{{fill:{c['warn']}}}
.door{{fill:none;stroke-width:1.6;stroke-dasharray:5 4}}
.door.open{{stroke:{c['warn']}}}.door.shut{{stroke:{c['ok']}}}
.stop{{fill:{c['surface']};stroke:{c['ok']};stroke-width:2}}
.stop-x{{stroke:{c['ok']};stroke-width:2}}
.door-t{{font-size:11px}}.open-t{{fill:{c['warn']}}}.shut-t{{fill:{c['ok']}}}
.num{{fill:{c['accent']}}}
.num-t{{fill:{c['surface']};font-family:{MONO};font-size:12px;font-weight:600}}
"""

def inner(svg):
    # strip the outer <svg ...> and </svg>
    body = re.sub(r"^<svg[^>]*>", "", svg.strip())
    return re.sub(r"</svg>\s*$", "", body)

def modes_svg(theme):
    heads = [("static", "default", False), ("passthrough", "callers' own tokens", False),
             ("exchange", "RFC 8693 · recommended with OAuth", True)]
    parts = []
    for i, (mode, sub, rec) in enumerate(heads):
        x = i * 360
        parts.append(f'<g transform="translate({x+10},0)">'
                     f'<text x="10" y="24" class="head">{mode}</text>'
                     f'<text x="10" y="42" class="head-s{" rec" if rec else ""}">{sub}</text>'
                     f'<g transform="translate(0,52)">{inner(panel(mode))}</g></g>')
    aria = ("Three ways the gateway authenticates to the relay. Static: the relay sees only the gateway, and callers' "
            "tokens do not work at the relay. Passthrough: the relay sees each caller, but their tokens also work at the "
            "relay directly. Exchange: the gateway swaps each caller's token at the identity provider for a relay token, "
            "so the relay sees each caller and their own tokens do not work there.")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 396" role="img" aria-label="{aria}">'
            f'<style>{css(THEMES[theme])}</style><rect width="1080" height="396" class="bg"/>'
            + "".join(parts) + "</svg>\n")

def flow_svg(theme):
    m = re.match(r'<svg viewBox="0 0 960 470" role="img" aria-label="([^"]*)">', flow)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 470" role="img" aria-label="{m.group(1)}">'
            f'<style>{css(THEMES[theme])}</style><rect width="960" height="470" class="bg"/>'
            + inner(flow) + "</svg>\n")

out = os.path.dirname(os.path.abspath(__file__))
os.makedirs(out, exist_ok=True)
for th in THEMES:
    open(f"{out}/relay-credential-modes-{th}.svg", "w").write(modes_svg(th))
    open(f"{out}/token-exchange-flow-{th}.svg", "w").write(flow_svg(th))
print(sorted(os.listdir(out)))
