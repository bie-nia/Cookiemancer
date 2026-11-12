package cookiemancer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Token capture, request rewriting, cookie jar helpers and external scripts. No Swing in here. */
final class Engine implements HttpHandler {
    static final String ACT_REPLACE_ALL = "CM Replace All Tokens";
    static final String ACT_DEL_TOKENS = "CM Delete Stored Tokens";
    static final String ACT_DEL_ALL = "CM Delete All Cookies";
    static final int MAX_SCRIPT_THREADS = 5;

    /** Callbacks into the UI; all may be invoked from non-EDT threads. */
    interface Listener {
        void tokenValuesChanged(int slot);

        void status(String text);

        void dirty();
    }

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Map<String, Optional<Pattern>> RX = new ConcurrentHashMap<>();

    private final MontoyaApi api;
    private final Config cfg;
    private final Map<Integer, Registration> tokenActions = new ConcurrentHashMap<>();
    private final AtomicInteger scriptThreads = new AtomicInteger();
    private volatile Listener listener = new Listener() {
        public void tokenValuesChanged(int slot) {
        }

        public void status(String text) {
        }

        public void dirty() {
        }
    };

    Engine(MontoyaApi api, Config cfg) {
        this.api = api;
        this.cfg = cfg;
    }

    void setListener(Listener l) {
        this.listener = l;
    }

    // ------------------------------------------------------------------ helpers

    static Pattern rx(String src, boolean ignoreCase) {
        if (src == null || src.isEmpty()) {
            return null;
        }
        if (RX.size() > 500) {
            RX.clear();
        }
        return RX.computeIfAbsent((ignoreCase ? "i:" : "s:") + src, k -> {
            try {
                return Optional.of(Pattern.compile(src, ignoreCase ? Pattern.CASE_INSENSITIVE : 0));
            } catch (PatternSyntaxException e) {
                return Optional.empty();
            }
        }).orElse(null);
    }

    /** Python-style "%s %s" formatting that never throws: first %s = prefix, second %s = token. */
    static String fmt(String format, String prefix, String token) {
        String f = format == null ? "" : format;
        int a = f.indexOf("%s");
        if (a < 0) {
            return f;
        }
        int b = f.indexOf("%s", a + 2);
        if (b < 0) {
            return f.substring(0, a) + prefix + f.substring(a + 2);
        }
        return f.substring(0, a) + prefix + f.substring(a + 2, b) + token + f.substring(b + 2);
    }

    static String tail(String s, int n) {
        return s.length() <= n ? s : s.substring(s.length() - n);
    }

    void log(String msg) {
        api.logging().logToOutput("[" + LocalDateTime.now().format(TS) + "] " + msg);
    }

    // ------------------------------------------------------------------ registration

    void registerAll() {
        api.http().registerHttpHandler(this);
        for (Config.Token t : cfg.tokens) {
            registerToken(t);
        }
        action(ACT_REPLACE_ALL, req -> {
            HttpRequest r = req;
            for (Config.Token t : cfg.tokens) {
                r = replace(t, r);
            }
            return r;
        });
        action(ACT_DEL_TOKENS, req -> {
            log("SHA_INVOKED: '" + ACT_DEL_TOKENS + "' - [" + deleteTokens() + " token value(s) deleted]");
            return req;
        });
        action(ACT_DEL_ALL, req -> {
            log("SHA_INVOKED: '" + ACT_DEL_ALL + "' - [" + deleteAllCookies() + " cookie(s) deleted from Burp cookie jar]");
            return req;
        });
        for (Config.Script s : cfg.scripts) {
            action(s.actionName(), req -> {
                runScript(s, s.actionName(), true);
                return req;
            });
        }
    }

    private Registration action(String name, Function<HttpRequest, HttpRequest> fn) {
        return api.http().registerSessionHandlingAction(new SessionHandlingAction() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public ActionResult performAction(SessionHandlingActionData data) {
                HttpRequest req = data.request();
                try {
                    req = fn.apply(req);
                } catch (Exception e) {
                    api.logging().logToError("Cookiemancer action '" + name + "' failed", e);
                }
                return ActionResult.actionResult(req, data.annotations());
            }
        });
    }

    void registerToken(Config.Token t) {
        tokenActions.put(t.slot, action(t.actionName(), req -> replace(t, req)));
    }

    void unregisterToken(Config.Token t) {
        Registration r = tokenActions.remove(t.slot);
        if (r != null) {
            r.deregister();
        }
        deleteJarCookies(c -> cfg.cookieDomain.equals(c.domain()) && t.cookieName().equals(c.name()));
    }

    // ------------------------------------------------------------------ capture

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        try {
            capture(resp);
        } catch (Exception e) {
            api.logging().logToError("Cookiemancer listener failed", e);
        }
        return ResponseReceivedAction.continueWith(resp);
    }

    /** Builds the capture pattern for the token's mode; null when the setting is empty or invalid. */
    static Pattern capturePattern(Config.Token t) {
        String v = t.capValue == null ? "" : t.capValue;
        if (v.trim().isEmpty()) {
            return null;
        }
        switch (t.capMode) {
            case Config.CAP_JSON:
                return rx("\"" + Pattern.quote(v.trim()) + "\"\\s*:\\s*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|([^\\s,}\\]\"]+))", false);
            case Config.CAP_HEADER:
                return rx("(?im)^" + Pattern.quote(v.trim().replaceAll(":$", "")) + "\\s*:[ \\t]*([^\\r\\n]*?)[ \\t]*\\r?$", false);
            case Config.CAP_COOKIE:
                return rx("(?im)^Set-Cookie:\\s*" + Pattern.quote(v.trim()) + "=([^;\\r\\n]*)", false);
            case Config.CAP_TEXT: {
                int star = v.indexOf('*');
                if (star < 0) {
                    return null;
                }
                String before = v.substring(0, star);
                String after = v.substring(star + 1);
                if (before.isEmpty() && after.isEmpty()) {
                    return null;
                }
                return rx((before.isEmpty() ? "" : Pattern.quote(before))
                        + (after.isEmpty() ? "([^\\s\"'<>&;]+)" : "(.+?)" + Pattern.quote(after)), false);
            }
            default:
                return rx(v, false);
        }
    }

    /** Where the capture pattern is applied: "Body", "Headers" or both. */
    static String captureSource(Config.Token t) {
        switch (t.capMode) {
            case Config.CAP_JSON:
                return "Body";
            case Config.CAP_HEADER:
            case Config.CAP_COOKIE:
                return "Headers";
            case Config.CAP_TEXT:
                return "Headers + body";
            default:
                return t.captureSource;
        }
    }

    /** Maps a Montoya ToolType name to one of {@link Config#TOOLS}. */
    static String toolGroup(String toolType) {
        switch (toolType) {
            case "PROXY":
                return "Proxy";
            case "REPEATER":
                return "Repeater";
            case "INTRUDER":
                return "Intruder";
            case "SCANNER":
                return "Scanner";
            case "SEQUENCER":
                return "Sequencer";
            case "EXTENSIONS":
                return "Extensions";
            default:
                return "Other";
        }
    }

    /** Sets a query parameter in a request path; appends it when missing and {@code add} is set. */
    static String setQueryParam(String path, String name, String token, boolean add) {
        String value = java.net.URLEncoder.encode(token, StandardCharsets.UTF_8);
        int q = path.indexOf('?');
        String base = q < 0 ? path : path.substring(0, q);
        String query = q < 0 ? "" : path.substring(q + 1);
        StringBuilder out = new StringBuilder();
        boolean found = false;
        if (!query.isEmpty()) {
            for (String part : query.split("&", -1)) {
                int eq = part.indexOf('=');
                String key = eq < 0 ? part : part.substring(0, eq);
                if (key.equals(name)) {
                    part = name + "=" + value;
                    found = true;
                }
                out.append(out.length() == 0 ? "" : "&").append(part);
            }
        }
        if (!found) {
            if (!add) {
                return path;
            }
            out.append(out.length() == 0 ? "" : "&").append(name).append("=").append(value);
        }
        return base + "?" + out;
    }

    static boolean urlMatches(Config.Token t, String url) {
        if (t.urlValue == null || t.urlValue.isEmpty()) {
            return true;
        }
        if (Config.URL_REGEX.equals(t.urlMode)) {
            Pattern p = rx(t.urlValue, false);
            return p != null && p.matcher(url).find();
        }
        return url.contains(t.urlValue);
    }

    /** Every token has its own listener: URL filter, response header filter, capture rule and path header. */
    private void capture(HttpResponseReceived resp) {
        HttpRequest req = null;
        String url = null;
        String tool = null;
        String toolGroup = null;
        String headers = null;
        String headersLower = null;
        String body = null;
        for (Config.Token t : cfg.tokens) {
            if (!t.enabled || !t.capture) {
                continue;
            }
            Pattern p = capturePattern(t);
            if (p == null) {
                continue;
            }
            if (req == null) {
                req = resp.initiatingRequest();
                url = req.url();
                tool = resp.toolSource().toolType().toolName();
                toolGroup = toolGroup(resp.toolSource().toolType().name());
            }
            if (!t.listensTo(toolGroup)) {
                continue;
            }
            if (t.urlCheck && !urlMatches(t, url)) {
                if (cfg.logRejects) {
                    log("- " + t.cookieName() + " REQ_URL_MATCH_FAILED: URL filter '" + t.urlValue + "' - [Tool:" + tool + "] [URL:" + url + "]");
                }
                continue;
            }
            if (headers == null) {
                StringBuilder hb = new StringBuilder();
                for (HttpHeader h : resp.headers()) {
                    hb.append(h.name()).append(": ").append(h.value()).append("\r\n");
                }
                headers = hb.toString();
                headersLower = headers.toLowerCase(Locale.ROOT);
            }
            if (t.respHeaderCheck && !headersLower.contains(t.respHeader.toLowerCase(Locale.ROOT))) {
                if (cfg.logRejects) {
                    log("- " + t.cookieName() + " RESP_HEADER_MATCH_FAILED: no response header contains '" + t.respHeader + "' - [Tool:" + tool + "] [URL:" + url + "]");
                }
                continue;
            }
            String source = captureSource(t);
            String text;
            if ("Headers".equals(source)) {
                text = headers;
            } else {
                if (body == null) {
                    body = resp.bodyToString();
                }
                text = "Body".equals(source) ? body : headers + "\r\n" + body;
            }
            Matcher m = p.matcher(text);
            if (!m.find()) {
                continue;
            }
            String value = m.group();
            for (int g = 1; g <= m.groupCount(); g++) {
                if (m.group(g) != null) {
                    value = m.group(g);
                    break;
                }
            }
            if (value.isEmpty()) {
                continue;
            }
            for (String path : requestPaths(req, t)) {
                setToken(t, path, value);
                log("+ READ_RESPONSE:" + t.cookieName() + " - [Tool:" + tool + "] [Token(-30):" + tail(value, 30)
                        + "] [Path:" + path + "] [ReqURL:" + req.path() + "]");
            }
        }
    }

    /** Path header setting is a plain header name ("SHP-Path"); anything else is treated as a regex with group 1. */
    private List<String> requestPaths(HttpRequest req, Config.Token t) {
        List<String> paths = new ArrayList<>();
        String setting = t.pathHeader == null ? "" : t.pathHeader.trim().replaceAll(":$", "");
        if (t.pathHeaderCheck && !setting.isEmpty()) {
            boolean plain = setting.matches("[\\w-]+");
            Pattern p = plain ? null : rx(t.pathHeader, true);
            for (HttpHeader h : req.headers()) {
                String path = null;
                if (plain) {
                    if (h.name().equalsIgnoreCase(setting)) {
                        path = h.value().trim();
                    }
                } else if (p != null) {
                    Matcher m = p.matcher(h.name() + ":" + h.value());
                    if (m.find()) {
                        path = (m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group()).trim();
                    }
                }
                if (path != null && !path.isEmpty() && !paths.contains(path)) {
                    paths.add(path);
                }
            }
        }
        if (paths.isEmpty()) {
            paths.add("/");
        }
        return paths;
    }

    void setToken(Config.Token t, String path, String value) {
        t.values.put(path, value);
        if (cfg.mirrorToJar) {
            try {
                api.http().cookieJar().setCookie(t.cookieName(), value, path, cfg.cookieDomain, null);
            } catch (Exception e) {
                api.logging().logToError("Cookiemancer could not mirror " + t.cookieName() + " to the cookie jar", e);
            }
        }
        listener.tokenValuesChanged(t.slot);
        listener.dirty();
    }

    // ------------------------------------------------------------------ lookup

    /** Result of picking the stored value that best fits a request path. */
    static final class Match {
        final String value;
        final String storedPath;
        final String how;
        final int count;

        Match(String value, String storedPath, String how, int count) {
            this.value = value;
            this.storedPath = storedPath;
            this.how = how;
            this.count = count;
        }
    }

    /** Same precedence as the original extension: single entry, exact dir, dir, parent dir, then "/". */
    static Match lookup(Map<String, String> values, String requestPath) {
        int n = values.size();
        if (n == 0) {
            return null;
        }
        if (n == 1) {
            Map.Entry<String, String> e = values.entrySet().iterator().next();
            return new Match(e.getValue(), e.getKey(), "1", n);
        }
        String path = requestPath == null ? "/" : requestPath.toLowerCase(Locale.ROOT);
        int q = path.indexOf('?');
        if (q >= 0) {
            path = path.substring(0, q);
        }
        int last = path.lastIndexOf('/');
        String dir = path.substring(0, last + 1);
        for (Map.Entry<String, String> e : values.entrySet()) {
            if (e.getKey().toLowerCase(Locale.ROOT).equals(dir)) {
                return new Match(e.getValue(), e.getKey(), "2", n);
            }
        }
        int prev = last <= 0 ? -1 : path.lastIndexOf('/', last - 1);
        String[] candidates = {
                dir,
                last <= 0 ? "/" : path.substring(0, last),
                prev < 0 ? "/" : path.substring(0, prev + 1),
                prev <= 0 ? "/" : path.substring(0, prev)
        };
        for (int i = 0; i < candidates.length; i++) {
            String c = candidates[i].isEmpty() ? "/" : candidates[i];
            for (Map.Entry<String, String> e : values.entrySet()) {
                if (e.getKey().toLowerCase(Locale.ROOT).contains(c)) {
                    return new Match(e.getValue(), e.getKey(), String.valueOf(3 + i), n);
                }
            }
        }
        String root = values.get("/");
        return root == null ? null : new Match(root, "/", "7", n);
    }

    // ------------------------------------------------------------------ replace

    HttpRequest replace(Config.Token t, HttpRequest req) {
        if (!t.enabled) {
            return req;
        }
        if (!t.h1 && !t.h2 && !t.body && !t.qp) {
            log("OPERATION TERMINATED: '" + t.actionName() + "' invoked but no header/body position is enabled.");
            return req;
        }
        Match m = lookup(t.snapshot(), req.pathWithoutQuery());
        if (m == null) {
            log("- " + t.cookieName() + ": no stored value for this request - [ReqURL:" + req.url() + "]");
            return req;
        }
        List<String> mods = new ArrayList<>();
        HttpRequest out = req;
        if (t.h1) {
            out = replaceHeader(out, t.h1Header, t.h1Value, t.h1Add, m.value, mods);
        }
        if (t.h2) {
            out = replaceHeader(out, t.h2Header, t.h2Value, t.h2Add, m.value, mods);
        }
        if (t.qp && t.qpName != null && !t.qpName.trim().isEmpty()) {
            String path = out.path();
            String changed = setQueryParam(path, t.qpName.trim(), m.value, t.qpAdd);
            if (!changed.equals(path)) {
                out = out.withPath(changed);
                mods.add("URL_" + t.qpName.trim());
            }
        }
        if (t.body && t.bodyValue != null && !t.bodyValue.isEmpty()) {
            String body = out.bodyToString();
            String changed = replaceBody(t, body, m.value);
            if (!changed.equals(body)) {
                out = out.withBody(changed);
                mods.add("BODY_" + t.bodyValue);
            }
        }
        if (mods.isEmpty()) {
            log("- " + t.cookieName() + "_OPERATION_TERMINATED: request has no known token position in header/body - [ReqURL:" + req.url() + "]");
            return req;
        }
        log("MODIFY_REQUEST:" + t.cookieName() + " - [Stored:" + m.count + "] [Match:" + m.how + "] [Token(-25):" + tail(m.value, 25)
                + "] [" + String.join(", ", mods) + "] [Path:" + m.storedPath + "] [ReqURL:" + req.url() + "]");
        return out;
    }

    static String fill(String template, String token) {
        String tpl = template == null || template.isEmpty() ? Config.TOKEN_MARK : template;
        return tpl.replace(Config.TOKEN_MARK, token);
    }

    /** Parameter mode handles form bodies (name=value) and JSON ("name":"value"); Regex mode replaces every match. */
    static String replaceBody(Config.Token t, String body, String token) {
        if (Config.BODY_REGEX.equals(t.bodyMode)) {
            Pattern p = rx(t.bodyValue, true);
            return p == null ? body : p.matcher(body).replaceAll(Matcher.quoteReplacement(fill(t.bodyTemplate, token)));
        }
        String name = Pattern.quote(t.bodyValue.trim());
        String tok = Matcher.quoteReplacement(token);
        String out = rx("(^|&)(" + name + ")=[^&]*", false).matcher(body).replaceAll("$1$2=" + tok);
        return rx("(\"" + name + "\"\\s*:\\s*\")(?:[^\"\\\\]|\\\\.)*(\")", false).matcher(out).replaceAll("$1" + tok + "$2");
    }

    private HttpRequest replaceHeader(HttpRequest req, String header, String template, boolean addIfMissing, String token, List<String> mods) {
        String name = header == null ? "" : header.trim().replaceAll(":$", "").trim();
        if (name.isEmpty()) {
            return req;
        }
        String value = fill(template, token);
        for (HttpHeader h : req.headers()) {
            if (h.name().equalsIgnoreCase(name)) {
                mods.add(name);
                return req.withUpdatedHeader(h.name(), value);
            }
        }
        if (addIfMissing) {
            mods.add("NEW_" + name);
            return req.withAddedHeader(name, value);
        }
        return req;
    }

    // ------------------------------------------------------------------ cookies

    /** Clears every stored Cookiemancer token value (and its mirror in the Burp cookie jar). */
    int deleteTokens() {
        int n = 0;
        for (Config.Token t : cfg.tokens) {
            n += clearToken(t);
        }
        return n;
    }

    int clearToken(Config.Token t) {
        int n;
        synchronized (t.values) {
            n = t.values.size();
            t.values.clear();
        }
        deleteJarCookies(c -> cfg.cookieDomain.equals(c.domain()) && t.cookieName().equals(c.name()));
        listener.tokenValuesChanged(t.slot);
        listener.dirty();
        return n;
    }

    void removeValue(Config.Token t, String path) {
        t.values.remove(path);
        deleteJarCookies(c -> cfg.cookieDomain.equals(c.domain()) && t.cookieName().equals(c.name()) && path.equals(c.path()));
        listener.tokenValuesChanged(t.slot);
        listener.dirty();
    }

    int deleteAllCookies() {
        int n = deleteJarCookies(c -> true);
        for (Config.Token t : cfg.tokens) {
            synchronized (t.values) {
                t.values.clear();
            }
            listener.tokenValuesChanged(t.slot);
        }
        listener.dirty();
        return n;
    }

    private int deleteJarCookies(java.util.function.Predicate<Cookie> which) {
        int n = 0;
        try {
            CookieJar jar = api.http().cookieJar();
            ZonedDateTime past = ZonedDateTime.now().minusYears(1);
            for (Cookie c : jar.cookies()) {
                if (which.test(c)) {
                    jar.setCookie(c.name(), "", c.path(), c.domain(), past);
                    n++;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Cookiemancer cookie jar cleanup failed", e);
        }
        return n;
    }

    // ------------------------------------------------------------------ scripts

    void runScript(Config.Script s, String label, boolean fromAction) {
        List<String> cmd = new ArrayList<>();
        for (String part : new String[]{s.cmd, s.arg1, s.arg2}) {
            if (part != null && !part.trim().isEmpty()) {
                cmd.add(part.trim());
            }
        }
        if (cmd.isEmpty() || s.cmd.trim().isEmpty()) {
            log("SCRIPT_NOT_CONFIGURED: '" + label + "' has no executable set.");
            return;
        }
        if (scriptThreads.get() >= MAX_SCRIPT_THREADS) {
            log("SCRIPT_MAX_LIMIT_REACHED: '" + label + "' not started, " + MAX_SCRIPT_THREADS + " scripts already running. ARGS:" + cmd);
            api.logging().raiseInfoEvent("Cookiemancer '" + label + "': max parallel scripts reached");
            return;
        }
        scriptThreads.incrementAndGet();
        boolean show = cfg.scriptShowOutput;
        boolean forget = cfg.scriptDontWait && !show;
        Thread th = new Thread(() -> {
            try {
                log("SCRIPT_EXEC_STARTED: '" + label + "' [THREADS:" + scriptThreads.get() + "/" + MAX_SCRIPT_THREADS + "] ARGS:" + cmd);
                ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
                if (forget) {
                    pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                    pb.start();
                    log("SCRIPT_EXEC_DETACHED: '" + label + "' started, not waiting for the result.");
                    return;
                }
                Process proc = pb.start();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                try (InputStream in = proc.getInputStream()) {
                    in.transferTo(out);
                }
                int code = proc.waitFor();
                if (show) {
                    log("SCRIPT_OUTPUT '" + label + "' >>>>>>>>\n" + new String(out.toByteArray(), StandardCharsets.UTF_8) + "\n<<<<<<<< SCRIPT_OUTPUT");
                }
                log("SCRIPT_EXEC_COMPLETED: '" + label + "' [exit code " + code + "]");
                listener.status("Script '" + label + "' finished with exit code " + code);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                log("SCRIPT_EXEC_ERROR: '" + label + "' ARGS:" + cmd + " [ERR: " + e + "]");
                api.logging().raiseErrorEvent("Cookiemancer '" + label + "': error running the script");
                listener.status("Script '" + label + "' failed: " + e.getMessage());
            } finally {
                scriptThreads.decrementAndGet();
            }
        }, "cookiemancer-script-" + s.n);
        th.setDaemon(true);
        th.start();
        if (fromAction && cfg.scriptBlock && !forget) {
            try {
                th.join(Math.max(1, cfg.scriptBlockTimeout) * 1000L);
                if (th.isAlive()) {
                    log("SCRIPT_WAIT_TIMEOUT: '" + label + "' still running after " + cfg.scriptBlockTimeout + "s, request continues.");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
