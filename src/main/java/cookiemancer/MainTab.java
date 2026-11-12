package cookiemancer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.util.LinkedHashMap;
import java.util.Map;

/** The "Cookiemancer" suite tab: collapsible sections for the listener, tokens, cookie jar and scripts. */
final class MainTab implements Engine.Listener {
    private final Config cfg;
    private final Engine engine;
    private final JPanel root = new JPanel(new BorderLayout());
    private final JLabel status = Ui.dimLabel("Ready.");
    private final JPanel tokenList = Ui.vstack();
    private final Map<Integer, TokenPanel> tokenPanels = new LinkedHashMap<>();
    private final JButton addToken = new JButton("+ Add token");
    private final Timer saveTimer;
    private final JLabel tokenCount = Ui.dimLabel("");

    MainTab(Config cfg, Engine engine, boolean loadedFromProject) {
        this.cfg = cfg;
        this.engine = engine;
        saveTimer = new Timer(400, e -> cfg.save());
        saveTimer.setRepeats(false);

        JButton expand = new JButton("Expand all");
        expand.addActionListener(e -> tokenPanels.values().forEach(t -> t.panel.setExpanded(true)));
        JButton collapse = new JButton("Collapse all");
        collapse.addActionListener(e -> tokenPanels.values().forEach(t -> t.panel.setExpanded(false)));
        addToken.addActionListener(e -> {
            Config.Token t = cfg.addToken();
            if (t != null) {
                engine.registerToken(t);
                rebuildTokens();
                status("Token-" + t.slot + " added - action '" + t.actionName() + "' registered.");
                dirty();
            }
        });
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.add(tokenCount);
        buttons.add(addToken);
        buttons.add(expand);
        buttons.add(collapse);

        JPanel top = new JPanel(new BorderLayout(12, 0));
        top.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        top.add(Ui.bold("Cookiemancer  " + Cookiemancer.VERSION), BorderLayout.WEST);
        top.add(status, BorderLayout.CENTER);
        top.add(buttons, BorderLayout.EAST);

        JPanel sections = Ui.vstack();
        sections.setBorder(BorderFactory.createEmptyBorder(0, 12, 12, 12));
        Ui.stack(sections, tokenList);
        Ui.stack(sections, generalSection());
        Ui.stack(sections, scriptsSection());
        rebuildTokens();

        Ui.ScrollBody bodyPanel = new Ui.ScrollBody();
        bodyPanel.add(sections, BorderLayout.NORTH);
        JScrollPane scroll = new JScrollPane(bodyPanel);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(20);

        root.add(top, BorderLayout.NORTH);
        root.add(scroll, BorderLayout.CENTER);
        status(loadedFromProject ? "Settings and tokens restored from the Burp project." : "No saved settings in this project - defaults loaded.");
    }

    JComponent component() {
        return root;
    }

    void flush() {
        saveTimer.stop();
        cfg.save();
    }

    // ------------------------------------------------------------------ Engine.Listener

    @Override
    public void tokenValuesChanged(int slot) {
        SwingUtilities.invokeLater(() -> {
            TokenPanel p = tokenPanels.get(slot);
            if (p != null) {
                p.refreshValues();
            }
        });
    }

    @Override
    public void status(String text) {
        SwingUtilities.invokeLater(() -> status.setText(text));
    }

    @Override
    public void dirty() {
        SwingUtilities.invokeLater(saveTimer::restart);
    }

    // ------------------------------------------------------------------ sections

    private void rebuildTokens() {
        tokenList.removeAll();
        Map<Integer, TokenPanel> keep = new LinkedHashMap<>(tokenPanels);
        tokenPanels.clear();
        for (Config.Token t : cfg.tokens) {
            TokenPanel tp = keep.get(t.slot);
            if (tp == null || tp.token != t) {
                tp = new TokenPanel(t, engine, this::dirty, () -> removeToken(t));
            }
            tokenPanels.put(t.slot, tp);
            Ui.stack(tokenList, tp.panel);
        }
        int n = cfg.tokens.size();
        tokenCount.setText("Tokens " + n + " / " + Config.MAX_TOKENS);
        addToken.setEnabled(n < Config.MAX_TOKENS);
        tokenList.revalidate();
        tokenList.repaint();
    }

    private void removeToken(Config.Token t) {
        int answer = JOptionPane.showConfirmDialog(root,
                "Remove " + t.title() + "?\nIts settings and stored values are deleted and the action '" + t.actionName()
                        + "' is unregistered.\nSession handling rules that use this action will stop working.",
                "Remove token", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) {
            return;
        }
        engine.unregisterToken(t);
        cfg.tokens.remove(t);
        rebuildTokens();
        status("Token-" + t.slot + " removed.");
        dirty();
    }

    private JComponent generalSection() {
        JPanel p = new JPanel(new GridBagLayout());
        JTextField domain = Ui.text(cfg.cookieDomain, v -> {
            cfg.cookieDomain = v.trim().isEmpty() ? "localhost" : v.trim();
            dirty();
        });
        JCheckBox mirror = Ui.check("Mirror tokens to the Burp cookie jar as TOKEN-N, domain", cfg.mirrorToJar, v -> {
            cfg.mirrorToJar = v;
            domain.setEnabled(v);
            dirty();
        });
        domain.setEnabled(cfg.mirrorToJar);
        JCheckBox rejects = Ui.check("Log responses rejected by token listeners (troubleshooting)", cfg.logRejects, v -> {
            cfg.logRejects = v;
            dirty();
        });
        JButton delTokens = new JButton("Delete stored tokens");
        delTokens.addActionListener(e -> status(engine.deleteTokens() + " stored token value(s) deleted."));
        JButton delAll = new JButton("Delete all cookies in the Burp cookie jar");
        delAll.addActionListener(e -> {
            int answer = JOptionPane.showConfirmDialog(root,
                    "Delete every cookie in the Burp cookie jar and all stored token values?",
                    "Delete all cookies", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (answer == JOptionPane.OK_OPTION) {
                status(engine.deleteAllCookies() + " cookie(s) deleted from the Burp cookie jar.");
            }
        });
        p.add(mirror, Ui.at(0, 0));
        p.add(domain, Ui.grow(1, 0, 1));
        p.add(rejects, Ui.at(0, 1));
        p.add(delTokens, Ui.at(0, 2));
        p.add(Ui.dimLabel("Session handling action:  " + Engine.ACT_DEL_TOKENS), Ui.grow(1, 2, 1));
        p.add(delAll, Ui.at(0, 3));
        p.add(Ui.dimLabel("Session handling action:  " + Engine.ACT_DEL_ALL), Ui.grow(1, 3, 1));
        p.add(Ui.dimLabel("Actions are used in Settings > Sessions > Session handling rules > Invoke a Burp extension. '"
                + Engine.ACT_REPLACE_ALL + "' applies every enabled token at once."), Ui.span(0, 4, 2));
        return new Ui.Collapsible("General and cookie jar", p, cfg.expGeneral, v -> {
            cfg.expGeneral = v;
            dirty();
        });
    }

    private JComponent scriptsSection() {
        JPanel p = Ui.vstack();

        JSpinner timeout = new JSpinner(new SpinnerNumberModel(Math.max(1, cfg.scriptBlockTimeout), 1, 3600, 5));
        timeout.addChangeListener(e -> {
            cfg.scriptBlockTimeout = (Integer) timeout.getValue();
            dirty();
        });
        JCheckBox forget = Ui.check("Do not wait for the result (run and forget)", cfg.scriptDontWait, v -> {
            cfg.scriptDontWait = v;
            dirty();
        });
        JCheckBox show = Ui.check("Print script output in the extension output", cfg.scriptShowOutput, v -> {
            cfg.scriptShowOutput = v;
            forget.setEnabled(!v);
            dirty();
        });
        forget.setEnabled(!cfg.scriptShowOutput);
        JCheckBox block = Ui.check("Hold the request until the script finishes, at most (s)", cfg.scriptBlock, v -> {
            cfg.scriptBlock = v;
            timeout.setEnabled(v);
            dirty();
        });
        timeout.setEnabled(cfg.scriptBlock);

        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        opts.add(show);
        opts.add(forget);
        opts.add(block);
        opts.add(timeout);
        Ui.stack(p, opts);
        p.add(Ui.gap(6));

        JPanel grid = new JPanel(new GridBagLayout());
        grid.add(Ui.dimLabel("Session handling action"), Ui.at(0, 0));
        grid.add(Ui.dimLabel("Executable"), Ui.grow(1, 0, 0.2));
        grid.add(Ui.dimLabel("Argument 1 (e.g. script path)"), Ui.grow(2, 0, 0.5));
        grid.add(Ui.dimLabel("Argument 2"), Ui.grow(3, 0, 0.3));
        int row = 1;
        for (Config.Script s : cfg.scripts) {
            grid.add(new JLabel(s.actionName()), Ui.at(0, row));
            grid.add(Ui.text(s.cmd, v -> {
                s.cmd = v;
                dirty();
            }), Ui.grow(1, row, 0.2));
            grid.add(Ui.text(s.arg1, v -> {
                s.arg1 = v;
                dirty();
            }), Ui.grow(2, row, 0.5));
            grid.add(Ui.text(s.arg2, v -> {
                s.arg2 = v;
                dirty();
            }), Ui.grow(3, row, 0.3));
            JButton run = new JButton("Run now");
            run.addActionListener(e -> {
                status("Running '" + s.actionName() + "' ...");
                engine.runScript(s, "BTN " + s.actionName(), false);
            });
            grid.add(run, Ui.at(4, row));
            row++;
        }
        Ui.stack(p, grid);
        JLabel note = Ui.dimLabel("At most " + Engine.MAX_SCRIPT_THREADS + " scripts run in parallel; further invocations are skipped.");
        note.setBorder(BorderFactory.createEmptyBorder(6, 4, 0, 0));
        Ui.stack(p, note);

        return new Ui.Collapsible("External scripts", p, cfg.expScripts, v -> {
            cfg.expScripts = v;
            dirty();
        });
    }
}
