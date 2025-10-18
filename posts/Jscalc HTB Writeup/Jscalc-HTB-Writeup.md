# Jscalc Challenges — HTB (easy) — Writeup

![screenshot](./Jscalc-1.png)

## Description

In the mysterious depths of the digital sea, a specialized JavaScript calculator has been crafted by tech-savvy squids. With multiple arms and complex problem-solving skills, these cephalopod engineers use it for everything from inkjet trajectory calculations to deep-sea math. Attempt to outsmart it at your own risk! 🦑

---

## TL;DR

I found an `eval()` usage in a Node.js-powered site which allowed remote code execution (RCE) via JavaScript. By requiring the Node `fs` module I listed the filesystem and read `/flag.txt`.

---

## What I did — step by step

### 1. Download & unzip

After downloading the challenge files and unzipping them we see the extracted files:

![](./image1)

Nothing interesting at first glance, so I inspected the web app.

### 2. Open the website

![](./image2)

### 3. Spot `eval()` usage

The site uses `eval()` to evaluate formulas. Quick reminder: `eval()` executes the string it's given in the caller's context — if that string can be influenced by an attacker, it can run arbitrary code in the environment of the webpage (or the Node process if running server-side).

![](./image3)

Because `package.json` showed the app runs on **Node.js**, server-side JavaScript execution opens the door to `require()` and the full Node API — meaning we can attempt RCE.

![](./image4)

### 4. Intercepting requests with Burp Suite

I inspected requests with Burp and noticed the endpoint accepts a `formula` parameter. I tested injecting `require('fs')` into that parameter.

![](./image5)

### 5. Using `fs` to explore the filesystem

Once `require('fs')` worked, I used `readdirSync()` to list directories. Example payload (sent through the `formula` parameter):

```js
require('fs').readdirSync('../').toString();
```

The response returned (root listing):

```
app, bin, dev, etc, flag.txt, home, lib, media, mnt, opt, proc, root, run, sbin, srv, sys, tmp, usr, var
```

This confirmed we were able to read server filesystem contents and that `/flag.txt` exists at the root.

### 6. Read the flag

Next payload to read the flag file:

```js
require('fs').readFileSync('/flag.txt').toString();
```

![](./image6)

And — boom — we obtained the flag.

---

## Commands / payloads used

* List root directory:

```js
require('fs').readdirSync('../').toString();
```

* Read the flag:

```js
require('fs').readFileSync('/flag.txt').toString();
```

---

## Notes & mitigation

* Avoid using `eval()` on untrusted input. If dynamic expression evaluation is required, use safe parsers or sandboxed interpreters.
* On Node.js, never expose `require`/internal modules via user-controllable evaluation contexts.
* Validate and sanitize any user-supplied expressions, or run them inside a strict sandbox like a separate process with minimal privileges.

---

## Final

Thanks for reading — that’s the full journey from spotting `eval()` to reading `/flag.txt` using Node's `fs` module.

*If you want, I can convert this to a single-file markdown post ready for your blog, or add front-matter and formatting for a specific static site generator.*
