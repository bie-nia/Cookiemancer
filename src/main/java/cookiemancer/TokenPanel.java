package cookiemancer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.util.Map;

/** Collapsible settings panel for one token slot. */
final class TokenPanel {
    final Config.Token token;
    final Ui.Collapsible panel;

    private final Engine engine;
    private final Runnable changed;
    private final JPanel body = Ui.vstack();
    private final DefaultTableModel valuesModel = new DefaultTableModel(new Object[]{"Path", "Value"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable valuesTable = new JTable(valuesModel);
    private final JScrollPane valuesScroll = new JScrollPane(valuesTable);
    private final JLabel preview1 = Ui.dimLabel("");
    private final JLabel preview2 = Ui.dimLabel("");
    private final JLabel preview3 = Ui.dimLabel("");
    private final JLabel preview4 = Ui.dimLabel("");
    private Runnable rowStates = () -> {
    };

    TokenPanel(Config.Token token, Engine engine, Runnable changed, Runnable onRemove) {
        this.token = token;
        this.engine = engine;
        this.changed = changed;

        Ui.stack(body, general());
        Ui.stack(body, capture());
        Ui.stack(body, replace());
        Ui.stack(body, values());

        panel = new Ui.Collapsible(token.title(), body, token.expanded, on -> {
            token.expanded = on;
            changed.run();
        });
        JCheckBox enabled = Ui.check("Enabled", token.enabled, v -> {
            token.enabled = v;
            refresh();
            changed.run();
        });
        JButton remove = new JButton("Remove");
        remove.addActionListener(e -> onRemove.run());
        panel.addControl(enabled);
        panel.addControl(remove);
        refresh();
    }

    private JPanel section(String title) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(4, 0, 4, 0),
                BorderFactory.createTitledBorder(title)));
        return p;
    }

    private JComponent general() {
        JPanel p = new JPanel(new GridBagLayout());
        p.add(new JLabel("Label"), Ui.at(0, 0));
        p.add(Ui.text(token.label, v -> {
            token.label = v;
            panel.setTitle(token.title());
            changed.run();
        }), Ui.grow(1, 0, 0.3));
        p.add(Ui.dimLabel("Session handling action:  " + token.actionName()), Ui.grow(2, 0, 0.7));
        return p;
    }

    private static String captureHint(String mode) {
        switch (mode) {
            case Config.CAP_JSON:
                return "Name of the JSON field in the response body, e.g.  access_token   (finds \"access_token\":\"...\")";
            case Config.CAP_HEADER:
                return "Name of the response header that carries the token, e.g.  X-CSRF-Token";
            case Config.CAP_COOKIE:
                return "Name of the cookie set by the response, e.g.  JSESSIONID";
            case Config.CAP_TEXT:
                return "Copy the text around the token and put * where the token is, e.g.  name=\"csrf\" value=\"*\"";
            default:
                return "Regular expression, group 1 is the token, e.g.  access_token\":\"(.+?)\"";
        }
    }

    private JComponent capture() {
        JPanel p = section("Listener - capture this token from responses");
        JLabel hint = Ui.dimLabel(captureHint(token.capMode));
        JTextField value = Ui.text(token.capValue, v -> {
            token.capValue = v;
            changed.run();
        });
        value.getDocument().addDocumentListener(onEdit(() -> Ui.markRegex(value, Config.CAP_REGEX.equals(token.capMode))));
        JComboBox<String> mode = new JComboBox<>(Config.CAP_MODES);
        mode.setSelectedItem(token.capMode);
        JComboBox<String> source = new JComboBox<>(new String[]{"Body", "Headers", "Headers + body"});
        source.setSelectedItem(token.captureSource);
        source.addActionListener(e -> {
            token.captureSource = String.valueOf(source.getSelectedItem());
            changed.run();
        });
        JLabel in = new JLabel("Search in");
        mode.addActionListener(e -> {
            token.capMode = String.valueOf(mode.getSelectedItem());
            hint.setText(captureHint(token.capMode));
            refresh();
            changed.run();
        });

        JTextField url = Ui.text(token.urlValue, v -> {
            token.urlValue = v;
            changed.run();
        });
        url.getDocument().addDocumentListener(onEdit(() -> Ui.markRegex(url, Config.URL_REGEX.equals(token.urlMode))));
        JComboBox<String> urlMode = new JComboBox<>(new String[]{Config.URL_CONTAINS, Config.URL_REGEX});
        urlMode.setSelectedItem(token.urlMode);
        urlMode.addActionListener(e -> {
            token.urlMode = String.valueOf(urlMode.getSelectedItem());
            refresh();
            changed.run();
        });
        JTextField hdr = Ui.text(token.respHeader, v -> {
            token.respHeader = v;
            changed.run();
        });
        JTextField path = Ui.text(token.pathHeader, v -> {
            token.pathHeader = v;
            changed.run();
        });
        JCheckBox on = Ui.check("Listen: capture token from", token.capture, v -> {
            token.capture = v;
            refresh();
            changed.run();
        });
        JCheckBox urlOn = Ui.check("Only when the request URL", token.urlCheck, v -> {
            token.urlCheck = v;
            refresh();
            changed.run();
        });
        JCheckBox hdrOn = Ui.check("Only when a response header contains", token.respHeaderCheck, v -> {
            token.respHeaderCheck = v;
            refresh();
            changed.run();
        });
        JCheckBox pathOn = Ui.check("Store under the path given in request header", token.pathHeaderCheck, v -> {
            token.pathHeaderCheck = v;
            refresh();
            changed.run();
        });
        p.add(on, Ui.at(0, 0));
        p.add(mode, Ui.grow(1, 0, 0));
        p.add(value, Ui.grow(2, 0, 1));
        p.add(in, Ui.at(3, 0));
        p.add(source, Ui.at(4, 0));
        p.add(hint, Ui.span(2, 1, 3));
        p.add(urlOn, Ui.at(0, 2));
        p.add(urlMode, Ui.grow(1, 2, 0));
        p.add(url, Ui.span(2, 2, 3));
        p.add(hdrOn, Ui.at(0, 3));
        p.add(hdr, Ui.span(1, 3, 4));
        p.add(pathOn, Ui.at(0, 4));
        p.add(path, Ui.span(1, 4, 4));
        JLabel from = new JLabel("Listen to responses from");
        JPanel tools = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        java.util.List<JCheckBox> toolBoxes = new java.util.ArrayList<>();
        for (String tool : Config.TOOLS) {
            JCheckBox box = Ui.check(tool, token.listensTo(tool), v -> {
                token.setTool(tool, v);
                changed.run();
            });
            toolBoxes.add(box);
            tools.add(box);
        }
        java.awt.GridBagConstraints fc = Ui.at(0, 5);
        fc.insets = new java.awt.Insets(2, 26, 2, 4);
        p.add(from, fc);
        java.awt.GridBagConstraints tc = Ui.span(1, 5, 4);
        tc.insets = new java.awt.Insets(2, 0, 2, 4);
        p.add(tools, tc);
        Runnable prev = rowStates;
        rowStates = () -> {
            prev.run();
            boolean en = token.enabled && token.capture;
            boolean rx = Config.CAP_REGEX.equals(token.capMode);
            mode.setEnabled(en);
            value.setEnabled(en);
            hint.setEnabled(en);
            in.setVisible(rx);
            source.setVisible(rx);
            in.setEnabled(en);
            source.setEnabled(en);
            urlOn.setEnabled(en);
            hdrOn.setEnabled(en);
            pathOn.setEnabled(en);
            urlMode.setEnabled(en && token.urlCheck);
            url.setEnabled(en && token.urlCheck);
            hdr.setEnabled(en && token.respHeaderCheck);
            path.setEnabled(en && token.pathHeaderCheck);
            from.setEnabled(en);
            toolBoxes.forEach(b -> b.setEnabled(en));
            Ui.markRegex(value, rx);
            Ui.markRegex(url, Config.URL_REGEX.equals(token.urlMode));
        };
        return p;
    }

    private static javax.swing.event.DocumentListener onEdit(Runnable r) {
        return new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                r.run();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                r.run();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                r.run();
            }
        };
    }

    private JComponent replace() {
        JPanel p = section("Replace in request  (runs when a session handling rule invokes '" + token.actionName() + "')");
        p.add(Ui.dimLabel("Position"), Ui.at(0, 0));
        p.add(Ui.dimLabel("Header / parameter name"), Ui.span(1, 0, 2));
        p.add(Ui.dimLabel("New value  ({token} = the token)"), Ui.grow(3, 0, 0.3));
        p.add(Ui.dimLabel("If missing"), Ui.at(4, 0));
        p.add(Ui.dimLabel("Result"), Ui.grow(5, 0, 0.4));

        // header 1
        JTextField n1 = Ui.text(token.h1Header, v -> {
            token.h1Header = v;
            edited();
        });
        JTextField f1 = Ui.text(token.h1Value, v -> {
            token.h1Value = v;
            edited();
        });
        JCheckBox a1 = Ui.check("Add it", token.h1Add, v -> {
            token.h1Add = v;
            changed.run();
        });
        JCheckBox c1 = Ui.check("Header 1", token.h1, v -> {
            token.h1 = v;
            refresh();
            changed.run();
        });
        p.add(c1, Ui.at(0, 1));
        p.add(n1, Ui.span(1, 1, 2));
        p.add(f1, Ui.grow(3, 1, 0.3));
        p.add(a1, Ui.at(4, 1));
        p.add(preview1, Ui.grow(5, 1, 0.4));

        // header 2
        JTextField n2 = Ui.text(token.h2Header, v -> {
            token.h2Header = v;
            edited();
        });
        JTextField f2 = Ui.text(token.h2Value, v -> {
            token.h2Value = v;
            edited();
        });
        JCheckBox a2 = Ui.check("Add it", token.h2Add, v -> {
            token.h2Add = v;
            changed.run();
        });
        JCheckBox c2 = Ui.check("Header 2", token.h2, v -> {
            token.h2 = v;
            refresh();
            changed.run();
        });
        p.add(c2, Ui.at(0, 2));
        p.add(n2, Ui.span(1, 2, 2));
        p.add(f2, Ui.grow(3, 2, 0.3));
        p.add(a2, Ui.at(4, 2));
        p.add(preview2, Ui.grow(5, 2, 0.4));

        // body
        JTextField rb = Ui.text(token.bodyValue, v -> {
            token.bodyValue = v;
            edited();
        });
        rb.getDocument().addDocumentListener(onEdit(() -> Ui.markRegex(rb, Config.BODY_REGEX.equals(token.bodyMode))));
        JTextField fb = Ui.text(token.bodyTemplate, v -> {
            token.bodyTemplate = v;
            edited();
        });
        JComboBox<String> bm = new JComboBox<>(new String[]{Config.BODY_PARAM, Config.BODY_REGEX});
        bm.setSelectedItem(token.bodyMode);
        bm.addActionListener(e -> {
            token.bodyMode = String.valueOf(bm.getSelectedItem());
            refresh();
            changed.run();
        });
        JCheckBox cb = Ui.check("Body", token.body, v -> {
            token.body = v;
            refresh();
            changed.run();
        });
        p.add(cb, Ui.at(0, 3));
        p.add(bm, Ui.grow(1, 3, 0));
        p.add(rb, Ui.grow(2, 3, 0.3));
        p.add(fb, Ui.grow(3, 3, 0.3));
        p.add(preview3, Ui.grow(5, 3, 0.4));

        // URL parameter
        JTextField qn = Ui.text(token.qpName, v -> {
            token.qpName = v;
            edited();
        });
        JCheckBox qa = Ui.check("Add it", token.qpAdd, v -> {
            token.qpAdd = v;
            changed.run();
        });
        JCheckBox cq = Ui.check("URL parameter", token.qp, v -> {
            token.qp = v;
            refresh();
            changed.run();
        });
        p.add(cq, Ui.at(0, 4));
        p.add(qn, Ui.span(1, 4, 2));
        p.add(qa, Ui.at(4, 4));
        p.add(preview4, Ui.grow(5, 4, 0.4));

        Runnable prev = rowStates;
        rowStates = () -> {
            prev.run();
            boolean en = token.enabled;
            boolean rx = Config.BODY_REGEX.equals(token.bodyMode);
            n1.setEnabled(en && token.h1);
            f1.setEnabled(en && token.h1);
            a1.setEnabled(en && token.h1);
            n2.setEnabled(en && token.h2);
            f2.setEnabled(en && token.h2);
            a2.setEnabled(en && token.h2);
            bm.setEnabled(en && token.body);
            rb.setEnabled(en && token.body);
            fb.setVisible(rx);
            fb.setEnabled(en && token.body);
            qn.setEnabled(en && token.qp);
            qa.setEnabled(en && token.qp);
            Ui.markRegex(rb, rx);
        };
        return p;
    }

    private JComponent values() {
        JPanel p = section("Stored values  (saved in the Burp project)");
        valuesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        valuesTable.setFillsViewportHeight(true);
        valuesTable.getColumnModel().getColumn(0).setPreferredWidth(160);
        valuesTable.getColumnModel().getColumn(1).setPreferredWidth(700);

        JTextField path = new JTextField("/", 10);
        JTextField value = new JTextField(30);
        JButton set = new JButton("Set value");
        set.addActionListener(e -> {
            String v = value.getText().trim();
            String pth = path.getText().trim();
            if (!v.isEmpty()) {
                engine.setToken(token, pth.isEmpty() ? "/" : pth, v);
                value.setText("");
            }
        });
        JButton removeSel = new JButton("Remove selected");
        removeSel.addActionListener(e -> {
            int row = valuesTable.getSelectedRow();
            if (row >= 0) {
                engine.removeValue(token, String.valueOf(valuesModel.getValueAt(row, 0)));
            }
        });
        JButton clear = new JButton("Clear all");
        clear.addActionListener(e -> engine.clearToken(token));

        JPanel manual = new JPanel(new GridBagLayout());
        manual.add(new JLabel("Path"), Ui.at(0, 0));
        manual.add(path, Ui.grow(1, 0, 0.2));
        manual.add(new JLabel("Value"), Ui.at(2, 0));
        manual.add(value, Ui.grow(3, 0, 0.8));
        manual.add(set, Ui.at(4, 0));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        buttons.add(removeSel);
        buttons.add(javax.swing.Box.createHorizontalStrut(6));
        buttons.add(clear);
        manual.add(buttons, Ui.at(5, 0));

        JPanel wrap = new JPanel(new BorderLayout(0, 4));
        wrap.add(valuesScroll, BorderLayout.CENTER);
        wrap.add(manual, BorderLayout.SOUTH);
        p.add(wrap, Ui.span(0, 0, 1));
        return p;
    }

    private void edited() {
        previews();
        changed.run();
    }

    private static String headerPreview(String name, String template) {
        String n = name == null ? "" : name.trim().replaceAll(":$", "").trim();
        return n.isEmpty() ? "" : n + ": " + Engine.fill(template, "<token>");
    }

    private void previews() {
        preview1.setText(token.h1 ? headerPreview(token.h1Header, token.h1Value) : "");
        preview2.setText(token.h2 ? headerPreview(token.h2Header, token.h2Value) : "");
        String b = "";
        if (token.body) {
            b = Config.BODY_REGEX.equals(token.bodyMode)
                    ? "each match  ->  " + Engine.fill(token.bodyTemplate, "<token>")
                    : token.bodyValue.trim() + "=<token>   or   \"" + token.bodyValue.trim() + "\":\"<token>\"";
        }
        preview3.setText(b);
        preview4.setText(token.qp && !token.qpName.trim().isEmpty() ? "?" + token.qpName.trim() + "=<token>" : "");
    }

    /** Re-syncs enabled states, previews, header summary and the values table. EDT only. */
    void refresh() {
        Ui.enableTree(body, token.enabled);
        rowStates.run();
        previews();
        refreshValues();
    }

    void refreshValues() {
        Map<String, String> vals = token.snapshot();
        valuesModel.setRowCount(0);
        String last = null;
        for (Map.Entry<String, String> e : vals.entrySet()) {
            valuesModel.addRow(new Object[]{e.getKey(), e.getValue()});
            last = e.getValue();
        }
        int rows = Math.max(1, Math.min(5, vals.size()));
        int h = valuesTable.getRowHeight() * rows + valuesTable.getTableHeader().getPreferredSize().height + 6;
        valuesScroll.setPreferredSize(new Dimension(200, h));

        StringBuilder s = new StringBuilder();
        if (!token.enabled) {
            s.append("disabled");
        } else {
            s.append(token.capture ? "listener on" : "listener off");
            int positions = (token.h1 ? 1 : 0) + (token.h2 ? 1 : 0) + (token.body ? 1 : 0) + (token.qp ? 1 : 0);
            s.append("  ·  ").append(positions).append(positions == 1 ? " position" : " positions");
        }
        s.append("  ·  ");
        if (vals.isEmpty()) {
            s.append("no value yet");
        } else {
            s.append(vals.size()).append(vals.size() == 1 ? " value" : " values").append("  …").append(Engine.tail(last, 16));
        }
        panel.setSummary(s.toString());
        panel.revalidate();
    }
}
