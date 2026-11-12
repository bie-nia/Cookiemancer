package cookiemancer;

import burp.api.montoya.persistence.PersistedObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/** All extension settings + captured token values. Persisted in the Burp project file. */
final class Config {
    static final int MAX_TOKENS = 10;
    static final int SCRIPTS = 3;
    private static final String ROOT = "shplus";

    /** Reads from / writes to a PersistedObject with the same call, so load and save cannot drift apart. */
    static final class Io {
        private final PersistedObject o;
        private final boolean load;

        Io(PersistedObject o, boolean load) {
            this.o = o;
            this.load = load;
        }

        String str(String k, String v) {
            if (load) {
                String s = o.getString(k);
                return s == null ? v : s;
            }
            o.setString(k, v == null ? "" : v);
            return v;
        }

        boolean bool(String k, boolean v) {
            if (load) {
                Boolean b = o.getBoolean(k);
                return b == null ? v : b;
            }
            o.setBoolean(k, v);
            return v;
        }

        int num(String k, int v) {
            if (load) {
                Integer i = o.getInteger(k);
                return i == null ? v : i;
            }
            o.setInteger(k, v);
            return v;
        }
    }

    static final String CAP_JSON = "JSON field";
    static final String CAP_HEADER = "Response header";
    static final String CAP_COOKIE = "Set-Cookie";
    static final String CAP_TEXT = "Text with *";
    static final String CAP_REGEX = "Regex";
    static final String[] CAP_MODES = {CAP_JSON, CAP_HEADER, CAP_COOKIE, CAP_TEXT, CAP_REGEX};
    static final String URL_CONTAINS = "contains";
    static final String URL_REGEX = "matches regex";
    static final String BODY_PARAM = "Parameter";
    static final String BODY_REGEX = "Regex";
    static final String TOKEN_MARK = "{token}";
    static final String[] TOOLS = {"Proxy", "Repeater", "Intruder", "Scanner", "Sequencer", "Extensions", "Other"};

    static final class Token {
        final int slot;
        volatile String label = "";
        volatile boolean enabled = true;
        volatile boolean expanded = true;

        // listener
        volatile boolean capture = true;
        volatile String capMode = CAP_JSON;
        volatile String capValue = "";
        volatile String captureSource = "Body";
        volatile boolean urlCheck = true;
        volatile String urlMode = URL_CONTAINS;
        volatile String urlValue = "/token";
        volatile boolean respHeaderCheck = true;
        volatile String respHeader = "Content-Type: application/json";
        volatile boolean pathHeaderCheck = true;
        volatile String pathHeader = "SHP-Path";
        /** Comma separated entries of {@link #TOOLS} this token listens to. */
        volatile String tools = String.join(",", TOOLS);

        // replace
        volatile boolean h1 = true;
        volatile String h1Header = "Authorization";
        volatile String h1Value = "Bearer {token}";
        volatile boolean h1Add = false;

        volatile boolean h2 = false;
        volatile String h2Header = "X-Auth-Token";
        volatile String h2Value = "{token}";
        volatile boolean h2Add = false;

        volatile boolean body = false;
        volatile String bodyMode = BODY_PARAM;
        volatile String bodyValue = "";
        volatile String bodyTemplate = "{token}";

        volatile boolean qp = false;
        volatile String qpName = "";
        volatile boolean qpAdd = true;

        /** path -> token value */
        final Map<String, String> values = Collections.synchronizedMap(new LinkedHashMap<>());

        Token(int slot) {
            this.slot = slot;
            capValue = "token" + slot;
            bodyValue = "token" + slot;
            qpName = "token" + slot;
            if (slot == 1) {
                qpName = "access_token";
                label = "access_token";
                capValue = "access_token";
                bodyValue = "access_token";
            } else if (slot == 2) {
                label = "refresh_token";
                capValue = "refresh_token";
                h1 = false;
                body = true;
                bodyValue = "refresh_token";
                qpName = "refresh_token";
            }
        }

        String cookieName() {
            return "TOKEN-" + slot;
        }

        String actionName() {
            return "Cookiemancer: Replace Token-" + slot;
        }

        String title() {
            String l = label == null ? "" : label.trim();
            return "Token-" + slot + (l.isEmpty() ? "" : "  ·  " + l);
        }

        Map<String, String> snapshot() {
            synchronized (values) {
                return new LinkedHashMap<>(values);
            }
        }

        void io(Io io) {
            label = io.str("label", label);
            enabled = io.bool("enabled", enabled);
            expanded = io.bool("expanded", expanded);
            capture = io.bool("capture", capture);
            capMode = io.str("capMode", capMode);
            capValue = io.str("capValue", capValue);
            captureSource = io.str("captureSource", captureSource);
            urlCheck = io.bool("urlCheck", urlCheck);
            urlMode = io.str("urlMode", urlMode);
            urlValue = io.str("urlValue", urlValue);
            respHeaderCheck = io.bool("respHeaderCheck", respHeaderCheck);
            respHeader = io.str("respHeader", respHeader);
            pathHeaderCheck = io.bool("pathHeaderCheck", pathHeaderCheck);
            pathHeader = io.str("pathHeader", pathHeader);
            h1 = io.bool("h1", h1);
            h1Header = io.str("h1Header", h1Header);
            h1Value = io.str("h1Value", h1Value);
            h1Add = io.bool("h1Add", h1Add);
            h2 = io.bool("h2", h2);
            h2Header = io.str("h2Header", h2Header);
            h2Value = io.str("h2Value", h2Value);
            h2Add = io.bool("h2Add", h2Add);
            body = io.bool("body", body);
            bodyMode = io.str("bodyMode", bodyMode);
            bodyValue = io.str("bodyValue", bodyValue);
            bodyTemplate = io.str("bodyTemplate", bodyTemplate);
            tools = io.str("tools", tools);
            qp = io.bool("qp", qp);
            qpName = io.str("qpName", qpName);
            qpAdd = io.bool("qpAdd", qpAdd);
        }

        boolean listensTo(String tool) {
            return ("," + tools + ",").contains("," + tool + ",");
        }

        void setTool(String tool, boolean on) {
            StringBuilder sb = new StringBuilder();
            for (String name : TOOLS) {
                if (name.equals(tool) ? on : listensTo(name)) {
                    sb.append(sb.length() == 0 ? "" : ",").append(name);
                }
            }
            tools = sb.toString();
        }

        /**
         * Reads a token saved by v2.0 (regex-only fields, optionally one global listener kept in {@code global})
         * and converts it to the current simple-mode fields, keeping the behaviour.
         */
        void migrate(PersistedObject own, PersistedObject global) {
            Io o = new Io(own, true);
            io(o);
            boolean globalListener = global.getBoolean("listenerEnabled") != null && own.getBoolean("urlCheck") == null;
            Io g = globalListener ? new Io(global, true) : o;
            urlCheck = g.bool("urlCheck", urlCheck);
            respHeaderCheck = g.bool("respHeaderCheck", respHeaderCheck);
            respHeader = g.str("respHeader", respHeader);
            pathHeaderCheck = g.bool("pathHeaderCheck", pathHeaderCheck);
            if (globalListener) {
                capture = capture && global.getBoolean("listenerEnabled");
            }
            String oldUrl = g.str("urlRegex", null);
            if (oldUrl != null) {
                urlMode = URL_REGEX;
                urlValue = oldUrl;
            }
            String oldPath = g.str("pathHeaderRegex", null);
            if (oldPath != null) {
                pathHeader = oldPath.endsWith(":(.*)") ? oldPath.substring(0, oldPath.length() - 5) : oldPath;
            }
            String oldCap = o.str("captureRegex", null);
            if (oldCap != null) {
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("^\"?([\\w.-]+)\"?:\"\\(\\.\\+\\?\\)\"$").matcher(oldCap);
                if (m.matches() && "Body".equals(captureSource)) {
                    capMode = CAP_JSON;
                    capValue = m.group(1);
                } else {
                    capMode = CAP_REGEX;
                    capValue = oldCap;
                }
            }
            String[] hv = oldHeader(o.str("h1Name", null), o.str("h1Format", "%s %s"));
            if (hv != null) {
                h1Header = hv[0];
                h1Value = hv[1];
            }
            hv = oldHeader(o.str("h2Name", null), o.str("h2Format", "%s %s"));
            if (hv != null) {
                h2Header = hv[0];
                h2Value = hv[1];
            }
            String oldBody = o.str("bodyRegex", null);
            if (oldBody != null) {
                String prefix = o.str("bodyPrefix", "");
                String format = o.str("bodyFormat", "%s%s");
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("^([\\w.-]+)=(\\\\w\\+|\\[\\^&\\]\\*)$").matcher(oldBody);
                if (m.matches() && prefix.equals(m.group(1) + "=") && "%s%s".equals(format)) {
                    bodyMode = BODY_PARAM;
                    bodyValue = m.group(1);
                } else {
                    bodyMode = BODY_REGEX;
                    bodyValue = oldBody;
                    bodyTemplate = Engine.fmt(format, prefix, TOKEN_MARK);
                }
            }
        }

        private static String[] oldHeader(String name, String format) {
            if (name == null) {
                return null;
            }
            String line = Engine.fmt(format, name, TOKEN_MARK);
            int colon = line.indexOf(':');
            if (colon <= 0) {
                return new String[]{name.replace(":", "").trim(), TOKEN_MARK};
            }
            return new String[]{line.substring(0, colon).trim(), line.substring(colon + 1).trim()};
        }
    }

    static final class Script {
        final int n;
        volatile String cmd = "";
        volatile String arg1 = "";
        volatile String arg2 = "";

        Script(int n) {
            this.n = n;
        }

        String actionName() {
            return "Cookiemancer: Run Script " + n;
        }

        void io(Io io) {
            cmd = io.str("cmd" + n, cmd);
            arg1 = io.str("arg1_" + n, arg1);
            arg2 = io.str("arg2_" + n, arg2);
        }
    }

    // ---- general
    volatile boolean logRejects = false;
    volatile boolean mirrorToJar = true;
    volatile String cookieDomain = "localhost";

    // ---- scripts
    volatile boolean scriptShowOutput = false;
    volatile boolean scriptDontWait = false;
    volatile boolean scriptBlock = false;
    volatile int scriptBlockTimeout = 120;
    final Script[] scripts = new Script[SCRIPTS];

    // ---- ui state
    volatile boolean expGeneral = false;
    volatile boolean expScripts = false;

    final List<Token> tokens = new CopyOnWriteArrayList<>();

    private final PersistedObject root;

    Config(PersistedObject root) {
        this.root = root;
        for (int i = 0; i < SCRIPTS; i++) {
            scripts[i] = new Script(i + 1);
        }
        scripts[0].cmd = "python3";
    }

    private void io(Io io) {
        logRejects = io.bool("logRejects", logRejects);
        mirrorToJar = io.bool("mirrorToJar", mirrorToJar);
        cookieDomain = io.str("cookieDomain", cookieDomain);
        scriptShowOutput = io.bool("scriptShowOutput", scriptShowOutput);
        scriptDontWait = io.bool("scriptDontWait", scriptDontWait);
        scriptBlock = io.bool("scriptBlock", scriptBlock);
        scriptBlockTimeout = io.num("scriptBlockTimeout", scriptBlockTimeout);
        expGeneral = io.bool("expGeneral", expGeneral);
        expScripts = io.bool("expScripts", expScripts);
        for (Script s : scripts) {
            s.io(io);
        }
    }

    /** @return true when settings were found in the project, false when defaults were used. */
    boolean load() {
        PersistedObject o = root == null ? null : root.getChildObject(ROOT);
        if (o == null) {
            tokens.add(new Token(1));
            tokens.add(new Token(2));
            return false;
        }
        io(new Io(o, true));
        List<Token> loaded = new ArrayList<>();
        for (int slot = 1; slot <= MAX_TOKENS; slot++) {
            PersistedObject to = o.getChildObject("t" + slot);
            if (to == null) {
                continue;
            }
            Token t = new Token(slot);
            if (to.getString("capMode") == null) {
                t.migrate(to, o);
            } else {
                t.io(new Io(to, true));
            }
            PersistedObject vals = to.getChildObject("values");
            if (vals != null) {
                for (String path : vals.stringKeys()) {
                    String v = vals.getString(path);
                    if (v != null) {
                        t.values.put(path, v);
                    }
                }
            }
            loaded.add(t);
        }
        tokens.addAll(loaded);
        return true;
    }

    synchronized void save() {
        if (root == null) {
            return;
        }
        PersistedObject o = PersistedObject.persistedObject();
        io(new Io(o, false));
        for (Token t : tokens) {
            PersistedObject to = PersistedObject.persistedObject();
            t.io(new Io(to, false));
            PersistedObject vals = PersistedObject.persistedObject();
            for (Map.Entry<String, String> e : t.snapshot().entrySet()) {
                vals.setString(e.getKey(), e.getValue());
            }
            to.setChildObject("values", vals);
            o.setChildObject("t" + t.slot, to);
        }
        root.setChildObject(ROOT, o);
    }

    Token token(int slot) {
        for (Token t : tokens) {
            if (t.slot == slot) {
                return t;
            }
        }
        return null;
    }

    /** Adds a token in the lowest free slot, keeping the list sorted. Returns null when all 10 are used. */
    Token addToken() {
        for (int slot = 1; slot <= MAX_TOKENS; slot++) {
            if (token(slot) == null) {
                Token t = new Token(slot);
                int idx = 0;
                while (idx < tokens.size() && tokens.get(idx).slot < slot) {
                    idx++;
                }
                tokens.add(idx, t);
                return t;
            }
        }
        return null;
    }
}
