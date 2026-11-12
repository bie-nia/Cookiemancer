package cookiemancer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.SwingUtilities;

/**
 * Cookiemancer - captures session tokens from responses and puts them back into requests.
 * Inspired by Session-Handler-Plus by Vinaya Kumar: https://github.com/V9Y1nf0S3C/Session-Handler-Plus
 */
public final class Cookiemancer implements BurpExtension {
    static final String VERSION = "v2.2";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Cookiemancer");

        Config cfg = new Config(api.persistence().extensionData());
        boolean loaded = cfg.load();
        Engine engine = new Engine(api, cfg);
        engine.registerAll();

        SwingUtilities.invokeLater(() -> {
            MainTab tab = new MainTab(cfg, engine, loaded);
            engine.setListener(tab);
            api.userInterface().applyThemeToComponent(tab.component());
            api.userInterface().registerSuiteTab("Cookiemancer", tab.component());
            api.extension().registerUnloadingHandler(tab::flush);
        });

        api.logging().logToOutput("Cookiemancer " + VERSION + " loaded - " + cfg.tokens.size() + " token(s), settings "
                + (loaded ? "restored from the Burp project." : "initialised with defaults."));
    }
}
