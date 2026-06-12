# LLMmon

*By Hassan Alkhafaji and Rakan Adnan · June 2026*

---

Every organization has a security stack built around visibility: firewalls, proxies, SIEM, EDR. You know what's crossing your network. You know what files are being opened. But the moment someone makes a call to an LLM API, that visibility disappears completely. The prompt leaves. The response arrives. Nobody logged it. Nobody reviewed it. It just... happened. that gap started keeping us up at night. So we closed it! with this Splunk app we made called **LLMmon**.

---

![](./Images/icon-removebg-preview.jpg)

## Introducing LLMmon

No Code Changes, No Agent changes, Simple setup to monitor any AI Agent that you have.

[https://splunkbase.splunk.com/app/8821](https://splunkbase.splunk.com/app/8821)

We built LLMmon as a Splunk app that sits between your LLM clients and your LLM providers. Every request and response passes through it. Everything gets logged into a Splunk index.

The concept is simple: instead of pointing your OpenAI SDK at `https://api.openai.com/v1`, you point it at `http://your-splunk-host:9000/v1`. LLMmon receives the request, logs it, forwards it upstream, logs the response, and returns it to the caller.

![](./Images/image.png)

---

## How It Works: Route Configuration

The first thing you set up is a **route** essentially a forwarding rule that tells LLMmon where to send traffic and with which credentials.

![](./Images/image%201.png)

![](./Images/image%202.png)

You click Configure Routes and you're taken to the LLMmon route manager then add Add Route.

Each route has:

- A **name** (just a label for your reference)
- A **provider** (OpenAI, Anthropic, OpenRouter, or Custom)
- An **upstream URL** (where to actually send the request)
- An **API key** (stored in Splunk, never exposed to clients)
- A **route condition** — either a catch-all default, or a header match for multi-provider routing

![](./Images/image%203.png)

![](./Images/image%204.png)

Say you want one team's traffic going to OpenAI and another team's traffic going to a local model. You just tell each client to include a specific header (like `X-Route-To: openai`), define the matching rule in LLMmon, and the gateway handles the rest.

Before traffic starts flowing, you need to tell the gateway which Splunk account to use for writing logs.

Open **Gateway Settings** from the app navigation, enter your Splunk username and password, and click **Save Credentials**.

![](./Images/image%205.png)

Splunk's secret store — never in the app code.

---

## Testing It With n8n

To actually validate the whole thing end-to-end, we connected n8n to LLMmon. n8n has an OpenAI Chat Model node that takes a base URL so we just pointed it at our gateway instead of OpenAI directly.

![](./Images/image%206.png)

![](./Images/image%207.png)

The connection test passed immediately. As far as n8n is concerned, it's talking to a standard OpenAI-compatible API. We then sent a test message through the n8n chat interface:

![](./Images/image%208.png)

A classic. But what matters here is what happened behind the scenes.

---

## What Splunk Actually Captured

We opened Splunk and searched `index="llmmon_logs"`.

![](./Images/image%209.png)

Two events. One for the request, one for the response. Let's look at them.

![](./Images/image%2010.png)

The **request event** (`event_type: llm_request`) captured:

- The full request body, including the system prompt and the user message ("hi tell me a joke")
- The model being requested
- The HTTP method and path
- A unique request ID

The **response event** (`event_type: llm_response`) captured:

- The full response body, including the joke text
- Token counts (75 prompt tokens, 16 completion tokens, 91 total)
- Response latency (7.961 seconds)
- The provider and model that actually handled the request

Everything you'd need for a security investigation sitting right there in Splunk, queryable with SPL, available to your existing alerts and correlation searches.

---

## What This Unlocks for Security Teams

Once the data is in Splunk, your SOC can work with it like any other data source.

You can build Splunk alerts. You can create correlation searches. You can tie this into your existing SIEM workflows. The data is there the hard part is done.

### Example: Catching Base64 in Prompts

Let's make this concrete. One real attack pattern is users pasting base64-encoded strings into an LLM chat and asking it to decode them a way to smuggle obfuscated content past keyword filters. We tested this exactly.

We sent the message `decode this U2VjcmV0MTIzdGVzdA==` and other testing inputs through the n8n chat. The model decoded it and handed back the plaintext.

![](./Images/image%2011.png)

Now here's where LLMmon earns its keep. Because every request is sitting in `llmmon_logs`, we can write a SPL search that scans all user messages for base64 patterns:

spl

```jsx
index="llmmon_logs" event_type="llm_request"
| rex field=request_body "\"role\\\":\\\"user\\\",\\\"content\\\":\\\"(?P<message>[^\\\"]+)\\\""
| rex field=message "(?P<base64_match>[A-Za-z0-9+/]{8,}={0,2})"
| where isnotnull(base64_match)
| table _time request_id model message base64_match
```

![](./Images/image%2012.png)

Every single request where a user fed a base64 string to the model timestamped, tied to a request ID, showing exactly what was sent. Turn this into a Splunk alert and your SOC gets notified in real time whenever it happens.

This is just one example. The same pattern applies to prompts containing IP addresses or internal hostnames, unusually long inputs that look like document dumps, messages matching known sensitive keywords. The data model is the same for all of them write the SPL, set the alert threshold, done.

### Example: Detecting Prompt Injection Attempts

Prompt injection is one of the most well-known LLM attack techniques — and one of the easiest to attempt. The idea is simple: craft a message that tries to override the model's original instructions and make it behave in a way it wasn't supposed to.

We tested this by sending the following message through the n8n chat:

![](./Images/image%2013.png)

The model responded. It didn't matter that there was a system prompt telling it to behave the user message overrode it. That exchange is now sitting in `llmmon_logs`, and we can write a rule to catch it.

```
index="llmmon_logs" event_type="llm_request"
| rex field=request_body "\"role\\\":\\\"user\\\",\\\"content\\\":\\\"(?P<message>[^\\\"]+)\\\""
| where isnotnull(message)
| eval injection_detected=if(
    match(lower(message), "ignore previous instructions") OR
    match(lower(message), "ignore all instructions") OR
    match(lower(message), "you are now in") OR
    match(lower(message), "jailbreak") OR
    match(lower(message), "developer mode") OR
    match(lower(message), "DAN mode") OR
    match(lower(message), "reveal your system prompt") OR
    match(lower(message), "act as if you have no restrictions"),
    "YES", null())
| where isnotnull(injection_detected)
| table _time request_id model message injection_detected
```

![](./Images/image%2014.png)

---

## Current State and What's Next

Here's where things stand right now:

- **Intercepts all LLM API calls** — acts as a fully transparent proxy
- **Token counting and usage tracking** — per model, per month
- **Full audit log** — requests and responses in a single Splunk index
- **Flexible routing** — forward traffic based on request headers, IP, or catch-all

---

## Installation

If you want to try this yourself:

1. Download and install the [LLMmon](https://splunkbase.splunk.com/app/8821) app from Splunkbase
2. make sure port 9000 is opened on splunk server
3. Restart Splunk when prompted
4. Navigate to **LLMmon Gateway** from the app launcher
5. Go to **Routes** and click **Configure Routes**
6. Add a route with your upstream LLM provider URL and API key and all needed configurations
7. Point your LLM clients at `http://<splunk-host>:9000/v1`

That's it. No code changes in your applications. The gateway handles everything. and log everything you need.

---

## Conclusion

The lack of visibility into LLM traffic is a real gap, and it's only getting bigger as AI gets wired into more workflows. LLMmon is our attempt to close that gap in a way that fits naturally into the security tooling most enterprises already have.

If your organization is running Splunk and you're starting to use LLMs at scale, this gives you a foundation to actually understand what's happening before you have to explain it to someone else.

The app is available on Splunkbase. Give it a try and let us know what you think.
[https://splunkbase.splunk.com/app/8821](https://splunkbase.splunk.com/app/8821)

---