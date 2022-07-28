package cz.muni.ics.oidc.server.ga4gh;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import cz.muni.ics.oidc.server.claims.ClaimSource;
import cz.muni.ics.oidc.server.claims.ClaimSourceInitContext;
import cz.muni.ics.oidc.server.claims.ClaimSourceProduceContext;
import cz.muni.ics.oidc.server.claims.ClaimUtils;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Class producing GA4GH Passport claim.
 * Configuration (replace [claimName] with the name of the claim):
 * <ul>
 *     <li><b>custom.claim.[claimName].source.endpoint</b>Endpoint producing GA4GH passport</li>
 *     <li><b>custom.claim.[claimName].source.username</b>Username to log in to the API</li>
 *     <li><b>custom.claim.[claimName].source.password</b>Password to log in to the API</li>
 *     <li><b>custom.claim.[claimName].source.param_name</b>String in endpoint's URL to be replaced with actual user's value</li>
 * </ul>
 *
 * @author Dominik Baranek <baranek@ics.muni.cz>
 */
@Slf4j
public class Ga4ghApiClaimSource extends ClaimSource {

    private static final String ENDPOINT = "endpoint";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String PARAM_NAME = "param_name";
    private static final String EPPN = "{eppn}";
    private final RestTemplate restTemplate;
    private final String endpoint;
    private final String authUsername;
    private final String authPassword;
    private final String userIdParamName;

    private final LoadingCache<String, JsonNode> cache;

    public Ga4ghApiClaimSource(ClaimSourceInitContext ctx) {
        super(ctx);

        this.endpoint = ClaimUtils.fillStringMandatoryProperty(ENDPOINT, ctx, getClaimName());
        this.authUsername = ClaimUtils.fillStringMandatoryProperty(USERNAME, ctx, getClaimName());
        this.authPassword = ClaimUtils.fillStringMandatoryProperty(PASSWORD, ctx, getClaimName());

        this.userIdParamName = ClaimUtils.fillStringPropertyOrDefaultVal(PARAM_NAME, ctx, EPPN);

        this.restTemplate = new RestTemplate(getClientHttpRequestFactory());
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(120, TimeUnit.SECONDS)
                .concurrencyLevel(10)
                .build(getCacheLoader());

        log.debug("{} - initialized GA4GH API claim source - endpoint '{}', username (auth) '{}', userIdParam '{}'", getClaimName(), endpoint, authUsername, userIdParamName);
    }

    @Override
    public Set<String> getAttrIdentifiers() {
        return Collections.emptySet();
    }

    @Override
    public JsonNode produceValue(ClaimSourceProduceContext pctx) {
        try {
            return this.cache.get(pctx.getSub());
        } catch (Exception e) {
            log.warn("{} - caught exception {}", getClaimName(), e.getMessage(), e);
        }
        return JsonNodeFactory.instance.nullNode();
    }

    private HttpComponentsClientHttpRequestFactory getClientHttpRequestFactory() {
        HttpComponentsClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory();
        clientHttpRequestFactory.setHttpClient(httpClient());

        return clientHttpRequestFactory;
    }

    private HttpClient httpClient() {
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(authUsername, authPassword));

        return HttpClientBuilder
                .create()
                .setDefaultCredentialsProvider(credentialsProvider)
                .build();
    }

    private CacheLoader<String, JsonNode> getCacheLoader() {
        return new CacheLoader<>() {
            @Override
            public JsonNode load(String userId) {
                try {
                    log.debug("{} - loading via API call; params - endpoint '{}', username (auth) '{}', userIdParam '{}'; user '{}'",
                            getClaimName(), endpoint, authUsername, userIdParamName, userId);
                    JsonNode result = restTemplate.getForObject(endpoint, JsonNode.class,
                            Collections.singletonMap(userIdParamName, userId));
                    log.debug("{} - loaded Passports(user: {}) - '{}'", getClaimName(), userId, result);
                    return result;
                } catch (RestClientException e) {
                    log.warn("{} - API call for user {} responded an error: {}", getClaimName(), userId, e.getMessage());
                }

                return JsonNodeFactory.instance.objectNode();
            }
        };
    }

}
