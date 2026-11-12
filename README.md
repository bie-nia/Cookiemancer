# Cookiemancer

Burp Suite extension (Montoya API, Java) that captures session tokens from responses and puts them back into requests through session handling rules. Up to 10 tokens, each with its own listener and replacement rules; everything is saved in the Burp project file.

Inspired by [Session-Handler-Plus](https://github.com/V9Y1nf0S3C/Session-Handler-Plus) by Vinaya Kumar. Cookiemancer is an independent rewrite in Java.

## Install

Download `cookiemancer-<version>.jar` from [Releases](../../releases), or build it:

```
./gradlew build        # -> build/libs/cookiemancer-<version>.jar
```

Burp → Extensions → Add → type **Java** → select the jar. A **CM** tab appears.

## Tokens

Add up to 10 tokens with **+ Add token**. Each token has its own collapsible panel.

**Listener** – where to read the token from:

| Mode | You enter | Example |
|---|---|---|
| JSON field | field name in the body | `access_token` |
| Response header | header name | `X-CSRF-Token` |
| Set-Cookie | cookie name | `JSESSIONID` |
| Text with * | surrounding text, `*` marks the token | `name="csrf" value="*"` |
| Regex | expression, group 1 = token | `token":"(.+?)"` |

JSON field searches the body, Response header and Set-Cookie search the headers, Text with * searches the whole response; for Regex pick the scope in *Search in*.

Optional filters: request URL (contains / regex), a response header, the Burp tools to listen to (Proxy, Repeater, Intruder, Scanner, Sequencer, Extensions, Other), and a request header that carries a path (`SHP-Path: /module/`) so the same token can hold different values for different parts of an application.

**Replace in request** – where to put the token:

- Header 1 / 2: header name + value with `{token}`, e.g. `Authorization` / `Bearer {token}`. *Add it* adds the header when it is missing.
- Body: *Parameter* (just the name; works for `name=value` and `"name":"value"`) or *Regex* + a template with `{token}`.
- URL parameter: query string parameter name; the value is URL-encoded. *Add it* appends the parameter when it is missing.

**Stored values** – captured values per path; they can be set or removed by hand.

## Session handling rules

Settings → Sessions → Session handling rules → Add → **Invoke a Burp extension**:

| Action | What it does |
|---|---|
| `CM Replace Token-N` | inserts token N |
| `CM Replace All Tokens` | inserts every enabled token |
| `CM Delete Stored Tokens` | deletes stored token values |
| `CM Delete All Cookies` | empties the Burp cookie jar |
| `CM Run Script 1–3` | runs an external command (e.g. a Selenium login) |

When a token has several values, the one whose path best matches the request URL is used, falling back to `/`.

## Other sections

- **General and cookie jar** – mirror tokens into the Burp cookie jar (`TOKEN-N`, domain `localhost`), log rejected responses, delete buttons.
- **External scripts** – three commands (executable + two arguments) with *Run now* for testing. Options: print script output, run-and-forget, hold the request until the script finishes. At most 5 scripts run in parallel.

## Persistence

Settings and token values are saved automatically in the Burp project file and restored when the project is opened. Temporary projects do not keep them.

Logs: Extensions → Installed → Cookiemancer → Output.

## License

MIT
