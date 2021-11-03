package cz.muni.ics.oidc.server.claims.modifiers;

import cz.muni.ics.oidc.server.claims.ClaimModifier;
import cz.muni.ics.oidc.server.claims.ClaimModifierInitContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Appending modifier. Appends the given text to the claim value.
 *
 * Configuration (replace [claimName] with the name of the claim and [modifierName] with the name of modifier):
 * <ul>
 *     <li><b>custom.claim.[claimName].modifier.[modifierName].append</b> - string to be appended to the value</li>
 * </ul>
 *
 * @author Martin Kuba <makub@ics.muni.cz>
 */
@SuppressWarnings("unused")
public class AppendModifier extends ClaimModifier {

	private static final Logger log = LoggerFactory.getLogger(AppendModifier.class);

	private static final String APPEND = "append";

	private final String appendText;

	public AppendModifier(ClaimModifierInitContext ctx) {
		super(ctx);
		appendText = ctx.getProperty(APPEND, "");
		log.debug("{}(modifier) - appendText: '{}'", getUnifiedName(), appendText);
	}

	@Override
	public String modify(String value) {
		String modified = value + appendText;
		log.trace("{} - modifying value '{}' by appending text '{}'", getUnifiedName(), value, appendText);
		log.trace("{} - new value: '{}", getUnifiedName(), modified);
		return modified;
	}

	@Override
	public String toString() {
		return getUnifiedName() + " - AppendModifier appending " + appendText;
	}

}
