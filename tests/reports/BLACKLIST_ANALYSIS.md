# CachyDPI Blacklist Analysis Report

> **Date:** 2026-04-10  
> **Test Method:** 3-stage (DNS → TCP → HTTPS), low parallelism (8-10), 15s timeout  
> **CachyDPI Version:** v1.0.0 (multi_fragment + disorder active)

---

## Overview

| Status | Count | Percentage | Details |
|--------|-------|------------|---------|
| ✅ Accessible | ~3700+ | 76%+ | Accessible with CachyDPI DPI bypass |
| ❌ Dead / Down | 386 | 7.7% | DNS unresolvable or server down → **removed from blacklist** |
| 🔴 ISP Blocked (IP) | 229 | 4.6% | IP-level block → CachyDPI cannot bypass |
| 🟢 ISP Blocked (SNI) | 5 | 0.1% | SNI block → **CachyDPI BYPASSES** ✅ |
| ☠️ Newly DNS Dead | 1 | 0.02% | Lost DNS resolution during testing |
| 🟡 Server Blocked (403) | 383 | 7.7% | Blocked by the server itself (geo-block, WAF) |
| 🟠 Server Error | ~145 | 2.9% | 4xx/5xx server errors |
| ⚡ Rate Limited | 9 | 0.2% | HTTP 429 - too many requests |

**Total tested:** 4999 domains  
**Active blacklist after cleanup:** 4851 domains

---

## ISP Blocked Sites - Detailed Analysis

### IP vs SNI Block Test

235 ISP-blocked sites were tested by establishing a TLS connection to each site's IP using `google.com` as the SNI:

| Block Type | Count | CachyDPI | Description |
|------------|-------|----------|-------------|
| **IP Blocked** | 229 | ❌ Cannot bypass | ISP blocks the target IP directly |
| **SNI Blocked** | 5 | ✅ BYPASSES | ISP only inspects SNI, CachyDPI bypasses via fragmentation |
| **DNS Dead** | 1 | - | `kuttymovies.com` no longer resolves via DNS |

### SNI Blocked Sites (ACCESSIBLE with CachyDPI) ✅

All on Google infrastructure — ISP cannot block these IPs (would break Google services):

| Domain | With CachyDPI | Description |
|--------|---------------|-------------|
| `googlevideo.com` | 302 | YouTube video CDN |
| `youtube-nocookie.com` | 404 | Privacy-enhanced YouTube embed |
| `youtube-ui.l.google.com` | accessible | YouTube UI CDN |
| `wide-youtube.l.google.com` | accessible | YouTube CDN |
| `googlecloud.com` | 404 | Google Cloud |

### IP Blocked Sites (229) - CachyDPI Ineffective

**Proof:** When testing `archive.is` (IP: 45.8.125.206), a TLS connection to the same IP with `google.com` SNI also times out. This proves the ISP is blocking the **IP address, not the SNI**.

```
# Normal test → timeout
curl https://archive.is → TLS handshake timeout

# Same IP, different SNI → STILL times out (proof of IP block)
curl --resolve google.com:443:45.8.125.206 https://google.com → timeout
```

### Why CachyDPI Cannot Bypass?

CachyDPI's bypass techniques are designed for **SNI-based DPI**:
- **Multi-fragment:** Splits TLS ClientHello into 3 fragments (hides SNI)
- **Disorder:** Sends fragments in reverse order
- **Passive DPI:** Drops fake RST/302 packets

However, **IP-level blocking** occurs BEFORE the TLS handshake. When the ISP sees the target IP, it drops all traffic — SNI is never even read.

### Workarounds

| Method | Effectiveness | Description |
|--------|---------------|-------------|
| **VPN** | ✅ Definitive | All traffic goes through encrypted tunnel, ISP cannot see target IP |
| **Tor** | ✅ Definitive | IP is hidden via onion routing |
| **SOCKS5 Proxy** | ✅ Definitive | Traffic is routed through proxy |
| **IPv6** | ⚠️ Partial | May work if ISP doesn't apply IPv6 blocking |
| **DNS-over-HTTPS** | ❌ Ineffective | Block is at IP level, not DNS |
| **ECH (Encrypted Client Hello)** | ❌ Ineffective | TLS-level, IP block occurs before |
| **Domain Fronting** | ⚠️ Site-dependent | Only for sites behind CDNs |

### Full List of ISP Blocked Sites (235 sites — 229 IP, 5 SNI, 1 DNS)

> **Note:** 5 SNI-blocked sites (googlecloud.com, googlevideo.com, wide-youtube.l.google.com, youtube-nocookie.com, youtube-ui.l.google.com) are accessible with CachyDPI.
> `kuttymovies.com` no longer resolves via DNS.

<details>
<summary>Show full list</summary>

| # | Domain | Category |
|---|--------|----------|
| 1 | 123movies.to | Movies |
| 2 | 1tamilmv.eu | Movies |
| 3 | 1x2gaming.com | Gaming |
| 4 | 2embed.to | Video embed |
| 5 | 4anime.to | Anime |
| 6 | 5dimes.eu | Gambling |
| 7 | 9anime.me | Anime |
| 8 | accountkit.com | Technology |
| 9 | accuweather.com | Weather |
| 10 | activision.com | Gaming |
| 11 | animedao.to | Anime |
| 12 | animefrenzy.net | Anime |
| 13 | anonymouse.org | Proxy |
| 14 | anydecentmusic.com | Music |
| 15 | appear.in | Video conferencing |
| 16 | archive.fo | Web archive |
| 17 | archive.is | Web archive |
| 18 | archive.li | Web archive |
| 19 | archive.md | Web archive |
| 20 | archive.ph | Web archive |
| 21 | archive.today | Web archive |
| 22 | archive.vn | Web archive |
| 23 | asianovel.com | Novel |
| 24 | avgle.com | Adult |
| 25 | azioncdn.net | CDN |
| 26 | babylon.finance | DeFi |
| 27 | bahis1000.com | Gambling |
| 28 | bahiscom.com | Gambling |
| 29 | bbci.co.uk | BBC CDN |
| 30 | betmatik.com | Gambling |
| 31 | bflix.gg | Movies |
| 32 | bflix.to | Movies |
| 33 | bitme.org | Torrent |
| 34 | b-ok.cc | Books |
| 35 | booksc.me | Books |
| 36 | booksc.org | Books |
| 37 | bookzz.org | Books |
| 38 | boomstudios.com | Comics |
| 39 | booongo.com | Gaming |
| 40 | boxnovel.com | Novel |
| 41 | briar.bramb.org | Secure messaging |
| 42 | bullguard.com | Security |
| 43 | callofduty.com | Gaming |
| 44 | cam4.com.br | Adult |
| 45 | camshowhub.com | Adult |
| 46 | canlisonuclar.com | Sports |
| 47 | casinoxy.com | Casino |
| 48 | cdn2.signal.org | Signal CDN |
| 49 | cdn.signal.org | Signal CDN |
| 50 | cfnm.net | Adult |
| 51 | chainlink.community | Crypto |
| 52 | challengeland.co | Education |
| 53 | chan.sankakucomplex.com | Adult |
| 54 | checkusernames.com | Tool |
| 55 | cineb.net | Movies |
| 56 | cloak-vpn.com | VPN |
| 57 | cmovies.ac | Movies |
| 58 | cockroachdb.com | Database |
| 59 | contentproxy.signal.org | Signal CDN |
| 60 | coverme.ws | Privacy |
| 61 | crackhub.site | Crack |
| 62 | crackstreams.biz | Sports streaming |
| 63 | debridplanet.com | File sharing |
| 64 | devrimcihareket.org | News |
| 65 | digital-rights.net | Digital rights |
| 66 | dizipal.cloud | TV series |
| 67 | dmcdn.net | Dailymotion CDN |
| 68 | dm-event.net | CDN |
| 69 | down-dog.com | App |
| 70 | downloadhub.guru | Downloads |
| 71 | dust.com | Movies |
| 72 | dwd.de | German weather |
| 73 | dynamite.com | Comics |
| 74 | dynamobet.com | Gambling |
| 75 | eagle.autodesk.com | Design |
| 76 | ekoru.org | Search engine |
| 77 | eksi.me | Dictionary |
| 78 | elasticbeanstalk.com | AWS |
| 79 | emuparadise.me | Emulation |
| 80 | extralunchmoney.com | Adult |
| 81 | fauna.com | Database |
| 82 | fbcdn.com | Facebook CDN |
| 83 | fbox.to | Movies |
| 84 | filmizle.org | Movies |
| 85 | fmoviesz.to | Movies |
| 86 | freevee.com | Video |
| 87 | freshcasino.com | Casino |
| 88 | friktion.fi | DeFi |
| 89 | gatsby.com | Web framework |
| 90 | gazetemanifesto.com | News |
| 91 | getsimplex.com | Crypto |
| 92 | gfxdomain.co | Graphics |
| 93 | givewater.com | Charity |
| 94 | gogo-play.net | Anime |
| 95 | golvar.co | Gambling |
| 96 | googlecloud.com | Google Cloud |
| 97 | googlevideo.com | YouTube CDN |
| 98 | grandcasino.com | Casino |
| 99 | guerrillamail.de | Anonymous email |
| 100 | hdfilmcehennemi.life | Movies |
| 101 | hegreart.com | Adult |
| 102 | herokuapp.com | Hosting |
| 103 | hesgoal.com | Sports streaming |
| 104 | hianime.to | Anime |
| 105 | hovarda.com | Gambling |
| 106 | hsus.org | Animal rights |
| 107 | huobi.com | Crypto exchange |
| 108 | icanw.org | Anti-nuclear weapons |
| 109 | idope.se | Torrent |
| 110 | ifile.it | File sharing |
| 111 | immutablex.com | NFT/Crypto |
| 112 | invest.com | Finance |
| 113 | isitdownrightnow.com | Status checker |
| 114 | jokerlivestream.net | Sports streaming |
| 115 | justinbet.com | Gambling |
| 116 | kat.am | Torrent |
| 117 | kbin.social | Fediverse |
| 118 | kickassanime.io | Anime |
| 119 | kickass.to | Torrent |
| 120 | kissanime.ru | Anime |
| 121 | konami.com | Gaming |
| 122 | kproxy.com | Proxy |
| 123 | kuttymovies.com | Movies |
| 124 | laine.app | App |
| 125 | library.lol | Books |
| 126 | lightshot.com | Screenshot |
| 127 | literotica.com | Adult |
| 128 | livejournal.com | Blog |
| 129 | livetv.sx | Sports streaming |
| 130 | lowkey.gg | Gaming |
| 131 | lxde.org | Linux desktop |
| 132 | magic-wormhole.io | File transfer |
| 133 | magnetdl.com | Torrent |
| 134 | maker.com | Automation |
| 135 | mamahd.best | Sports streaming |
| 136 | mangakakalot.com | Manga |
| 137 | mangalife.us | Manga |
| 138 | manganato.com | Manga |
| 139 | mangapark.to | Manga |
| 140 | manhua.dmzj.com | Manga |
| 141 | memegenerator.net | Meme |
| 142 | meteo.fr | Weather |
| 143 | mkdocs.org | Documentation |
| 144 | monoschinos.com | Anime |
| 145 | monova.org | Torrent |
| 146 | movierulz.com | Movies |
| 147 | moviesjoy.net | Movies |
| 148 | myflixer.to | Movies |
| 149 | myspace.com | Social media |
| 150 | neeva.com | Search engine |
| 151 | net-a-porter.com | Fashion |
| 152 | netflixtechblog.com | Blog |
| 153 | nio.com | Automotive |
| 154 | notwhat.cd | Music |
| 155 | nxbrew.com | Gaming |
| 156 | nxmac.com | Mac software |
| 157 | oafindr.com | Academic |
| 158 | openlearn.open.ac.uk | Education |
| 159 | opsfet.ch | Security |
| 160 | oshi.at | File sharing |
| 161 | porndune.com | Adult |
| 162 | pornzo.com | Adult |
| 163 | purpur.pl | Minecraft |
| 164 | pururin.to | Adult |
| 165 | quickmeme.com | Meme |
| 166 | rambler.ru | Russian portal |
| 167 | readlightnovel.me | Novel |
| 168 | readlightnovel.org | Novel |
| 169 | readm.org | Manga |
| 170 | reddit.map.fastly.net | Reddit CDN |
| 171 | remote.co | Job listings |
| 172 | renzo.xyz | DeFi |
| 173 | robo3t.org | MongoDB GUI |
| 174 | rocket-pool.io | Crypto |
| 175 | sabayon.org | Linux distro |
| 176 | sankakucomplex.com | Adult |
| 177 | scrivener.com | Software |
| 178 | seedpeer.me | Torrent |
| 179 | sendspace.com | File sharing |
| 180 | session.org | Secure messaging |
| 181 | sfsite.com | Sci-fi |
| 182 | sfu.voip.signal.org | Signal VoIP |
| 183 | shareflare.net | File sharing |
| 184 | simplednscrypt.org | DNS encryption |
| 185 | skidrow-games.com | Crack |
| 186 | solpad.finance | DeFi |
| 187 | spankbang.cc | Adult |
| 188 | sportbetting.ag | Gambling |
| 189 | squadov.gg | Gaming |
| 190 | stitcher.com | Podcast |
| 191 | storage.signal.org | Signal CDN |
| 192 | streameast.io | Sports streaming |
| 193 | streamhub.to | Video |
| 194 | streamlare.com | Video |
| 195 | stylus.openstyles.org | Browser extension |
| 196 | sushiswap.fi | DeFi |
| 197 | tea-tv.com | Movies |
| 198 | thepiratebay.se | Torrent |
| 199 | tinyletter.com | Email |
| 200 | torlock.com | Torrent |
| 201 | torrentz2.me | Torrent |
| 202 | totalsportek.com | Sports streaming |
| 203 | trtnet.com | TRT alt domain |
| 204 | ul.to | File sharing |
| 205 | unblockit.foo | Proxy |
| 206 | unblocksites.co | Proxy |
| 207 | unibytes.com | File sharing |
| 208 | uploaded.net | File sharing |
| 209 | upstream.to | Video |
| 210 | uptobox.com | File sharing |
| 211 | uptostream.com | Video |
| 212 | usembassy.gov | US embassy |
| 213 | usnews.com | News |
| 214 | viewasian.co | Drama |
| 215 | volafile.org | File sharing |
| 216 | vpnarea.com | VPN |
| 217 | vporn.com | Adult |
| 218 | vtt.tumblr.com | Tumblr CDN |
| 219 | weakstreams.com | Sports streaming |
| 220 | weatherapi.com | Weather API |
| 221 | webproxy.to | Proxy |
| 222 | wide-youtube.l.google.com | YouTube CDN |
| 223 | windows.net | Azure CDN |
| 224 | wnmtl.org | Novel |
| 225 | wonobo.com | Virtual tour |
| 226 | wonodds.com | Gambling |
| 227 | worldaffairsjournal.org | Magazine |
| 228 | worldweatheronline.com | Weather |
| 229 | writefree.ly | Blog |
| 230 | youtube-nocookie.com | YouTube CDN |
| 231 | youtube-ui.l.google.com | YouTube CDN |
| 232 | yuzu-emu.org | Emulator |
| 233 | zishy.com | Adult |
| 234 | z-lib.org | Books |
| 235 | zoro.to | Anime |

</details>

---

## Server Blocked Sites (383 - HTTP 403)

These sites are blocked by the **server itself**. Typically:
- Geographic block (Turkish IPs rejected)
- WAF/Bot protection
- Access restrictions

These are **not** ISP blocks but server-side blocks. There is nothing CachyDPI can do — the issue is not with the ISP but with the target server.

---

## Working Bypass Strategies

### Current Configuration (Effective)
```toml
[strategies]
passive_dpi = true        # Drop fake RST/302 packets
multi_fragment = true      # Split ClientHello into 3 fragments
disorder = true            # Send fragments in reverse order
auto_ttl = true           # Automatic TTL detection
fake_packet_enabled = false # Disabled (breaks connections on Turkish ISPs)
desync_first = false       # Disabled (fake RST treated as real RST by ISP)
```

### Summary
- **76%+** of sites accessible with CachyDPI (SNI-based DPI bypass)
- **5 sites** SNI-blocked but **bypassed by CachyDPI** (Google infrastructure domains)
- **229 sites** IP-blocked (CachyDPI cannot bypass → VPN/Tor required)
- **383 sites** server-blocked (not CachyDPI's scope)
- **386 sites** dead (cleaned from blacklist)

### ISP Blocking Mechanism Summary

```
The ISP DPI system operates on two layers:

1. IP Block (229 sites):
   Target IP → ISP firewall → ALL traffic dropped
   CachyDPI ineffective — packets blocked at IP level

2. SNI Block (all other blocked sites):
   TLS ClientHello → ISP DPI → SNI read → block if matched
   CachyDPI EFFECTIVE — SNI fragmentation fools the ISP

3. DNS Poisoning:
   DNS query → ISP DNS → fake response returned
   CachyDPI EFFECTIVE — if DoH/DoT is used
```

---

## Deploy Command

To activate the cleaned blacklist:

```bash
sudo cp /tmp/blacklist_cleaned.txt /etc/cachydpi/blacklist.txt
sudo systemctl restart cachydpi
```

Or from the workspace's current file:
```bash
sudo cp config/blacklist.txt /etc/cachydpi/blacklist.txt
sudo systemctl restart cachydpi
```
