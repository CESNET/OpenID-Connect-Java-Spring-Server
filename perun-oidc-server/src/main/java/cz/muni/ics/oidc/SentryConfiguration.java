package cz.muni.ics.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import cz.muni.ics.oidc.server.configurations.PerunOidcConfig;
import io.sentry.Sentry;
import java.io.File;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

@Slf4j
public class SentryConfiguration implements InitializingBean {

    private final String configFileLocation;
    private final String appVersion;

    public SentryConfiguration(PerunOidcConfig perunOidcConfig) {
        this.configFileLocation = perunOidcConfig.getSentryConfigFileLocation();
        this.appVersion = perunOidcConfig.getPerunOIDCVersion();
    }

    @Override
    public void afterPropertiesSet() {
        if (!StringUtils.hasText(configFileLocation)) {
            log.debug("Sentry will not be configured, configuration file location not provided");
            return;
        }
        JsonNode configFile = parseConfigFile(configFileLocation);
        if (configFile == null || configFile.isNull()) {
            log.debug("Sentry will not be configured, could not parse configuration file");
            return;
        }
        final String dsn = configFile.path("dsn").asText();
        log.debug("Initializing Sentry '{}'", dsn);

        Sentry.init(options -> {
            options.setDsn(dsn);
            options.setDebug(true);
            options.setRelease(appVersion);
            options.setEnableUncaughtExceptionHandler(true);
        });
    }

    private JsonNode parseConfigFile(String file)
    {
        YAMLMapper mapper = new YAMLMapper();
        try {
            return mapper.readValue(new File(file), JsonNode.class);
        } catch (IOException ex) {
            log.error("Cannot read Sentry config file", ex);
        }
        return JsonNodeFactory.instance.nullNode();
    }
}
