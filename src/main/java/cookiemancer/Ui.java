package cookiemancer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.Scrollable;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Small Swing building blocks shared by the tab and the token panels. */
final class Ui {
    static final Color BAD = new Color(0xD9, 0x53, 0x4F);

    private Ui() {
    }

    static Color line() {
        Color c = UIManager.getColor("Separator.foreground");
        if (c == null) {
            c = UIManager.getColor("controlShadow");
        }
        return c == null ? Color.GRAY : c;
    }

    static Color dim() {
        Color c = UIManager.getColor("Label.disabledForeground");
        return c == null ? Color.GRAY : c;
    }

    static JLabel dimLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(dim());
        return l;
    }

    static JLabel bold(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        return l;
    }

    /** Vertical stack whose children keep their preferred height and fill the width. */
    static JPanel vstack() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        return p;
    }

    static void stack(JPanel stack, JComponent c) {
        c.setAlignmentX(Component.LEFT_ALIGNMENT);
        stack.add(c);
    }

    static GridBagConstraints at(int x, int y) {
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = x;
        g.gridy = y;
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.WEST;
        return g;
    }

    /** Cell that takes the given share of spare width and fills it. */
    static GridBagConstraints grow(int x, int y, double weight) {
        GridBagConstraints g = at(x, y);
        g.weightx = weight;
        g.fill = GridBagConstraints.HORIZONTAL;
        return g;
    }

    static GridBagConstraints span(int x, int y, int width) {
        GridBagConstraints g = grow(x, y, 1);
        g.gridwidth = width;
        return g;
    }

    static JTextField text(String init, Consumer<String> set) {
        JTextField f = new JTextField(init == null ? "" : init, 12);
        f.getDocument().addDocumentListener(new DocumentListener() {
            private void go() {
                set.accept(f.getText());
            }

            public void insertUpdate(DocumentEvent e) {
                go();
            }

            public void removeUpdate(DocumentEvent e) {
                go();
            }

            public void changedUpdate(DocumentEvent e) {
                go();
            }
        });
        return f;
    }

    /** Marks the field red (compiler message as tooltip) when it should hold a regex and does not compile. */
    static void markRegex(JTextField f, boolean isRegex) {
        String err = null;
        if (isRegex) {
            try {
                Pattern.compile(f.getText());
            } catch (PatternSyntaxException e) {
                err = e.getDescription();
            }
        }
        f.setForeground(err == null ? UIManager.getColor("TextField.foreground") : BAD);
        f.setToolTipText(err == null ? null : "Invalid regex: " + err);
    }

    static JCheckBox check(String label, boolean init, Consumer<Boolean> set) {
        JCheckBox c = new JCheckBox(label, init);
        c.addActionListener(e -> set.accept(c.isSelected()));
        return c;
    }

    static void enableTree(Component c, boolean on) {
        c.setEnabled(on);
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) {
                enableTree(child, on);
            }
        }
    }

    /** Panel for a JScrollPane viewport: follows the viewport width, scrolls only vertically. */
    static final class ScrollBody extends JPanel implements Scrollable {
        ScrollBody() {
            super(new BorderLayout());
        }

        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        public int getScrollableUnitIncrement(Rectangle r, int orientation, int direction) {
            return 20;
        }

        public int getScrollableBlockIncrement(Rectangle r, int orientation, int direction) {
            return Math.max(20, r.height - 40);
        }

        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    /** Section with a clickable header that shows/hides its content. */
    static final class Collapsible extends JPanel {
        private final JLabel arrow = new JLabel();
        private final JLabel title = new JLabel();
        private final JLabel summary = new JLabel();
        private final JPanel controls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        private final JComponent content;
        private final Consumer<Boolean> onToggle;
        private boolean expanded;

        Collapsible(String titleText, JComponent content, boolean expanded, Consumer<Boolean> onToggle) {
            super(new BorderLayout());
            this.content = content;
            this.onToggle = onToggle;
            this.expanded = expanded;

            title.setText(titleText);
            title.setFont(title.getFont().deriveFont(Font.BOLD));
            summary.setForeground(dim());

            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            left.setOpaque(false);
            left.add(arrow);
            left.add(title);
            left.add(summary);
            controls.setOpaque(false);

            JPanel header = new JPanel(new BorderLayout());
            header.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 4));
            header.add(left, BorderLayout.CENTER);
            header.add(controls, BorderLayout.EAST);
            header.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            MouseAdapter click = new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    setExpanded(!Collapsible.this.expanded);
                }
            };
            header.addMouseListener(click);
            left.addMouseListener(click);

            content.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(1, 0, 0, 0, line()),
                    BorderFactory.createEmptyBorder(8, 10, 10, 10)));

            setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createEmptyBorder(4, 0, 4, 0),
                    BorderFactory.createLineBorder(line())));
            add(header, BorderLayout.NORTH);
            add(content, BorderLayout.CENTER);
            apply();
        }

        private void apply() {
            Icon icon = UIManager.getIcon(expanded ? "Tree.expandedIcon" : "Tree.collapsedIcon");
            arrow.setIcon(icon);
            arrow.setText(icon == null ? (expanded ? "v" : ">") : null);
            content.setVisible(expanded);
            revalidate();
            repaint();
        }

        void setExpanded(boolean on) {
            if (expanded == on) {
                return;
            }
            expanded = on;
            apply();
            if (onToggle != null) {
                onToggle.accept(on);
            }
        }

        void setTitle(String t) {
            title.setText(t);
        }

        void setSummary(String s) {
            summary.setText(s == null ? "" : s);
        }

        void addControl(JComponent c) {
            controls.add(c);
        }

        @Override
        public Dimension getMaximumSize() {
            return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
        }
    }

    static Component gap(int h) {
        return Box.createVerticalStrut(h);
    }
}
