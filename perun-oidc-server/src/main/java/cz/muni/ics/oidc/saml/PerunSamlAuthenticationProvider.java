package cz.muni.ics.oidc.saml;

import cz.muni.ics.oidc.models.PerunUser;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

@Slf4j
public class PerunSamlAuthenticationProvider extends SAMLAuthenticationProvider {

    private static final GrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");
    private static final GrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");

    private final List<Long> adminIds = new ArrayList<>();

    public PerunSamlAuthenticationProvider(List<String> adminIds) {
        for (String id : adminIds) {
            long l = Long.parseLong(id);
            this.adminIds.add(l);
            log.debug("added user {} as admin", l);
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            return super.authenticate(authentication);
        } catch (Exception e) {
            return new SamlAuthenticationExceptionAuthenticationToken(e);
        }
    }

    @Override
    protected Object getPrincipal(SAMLCredential credential, Object userDetail) {
        PerunUser user = (PerunUser) userDetail;
        return new SamlPrincipal(user.getId(), credential, getEntitlements(credential, userDetail));
    }

    @Override
    public Collection<? extends GrantedAuthority> getEntitlements(SAMLCredential credential, Object userDetail) {
        PerunUser user = (PerunUser) userDetail;
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(ROLE_USER);
        if (adminIds.contains(user.getId())) {
            authorities.add(ROLE_ADMIN);
            log.debug("adding admin role for user with Perun ID: {}", user.getId());
        }
        return authorities;
    }

}
