package cz.muni.ics.openid.connect.config;

import static org.junit.Assert.assertEquals;

import java.text.MessageFormat;
import java.util.Locale;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

@RunWith(MockitoJUnitRunner.class)
public class TestJsonMessageSource {

	@InjectMocks
	private JsonMessageSource jsonMessageSource;

	@Spy
	private ConfigurationPropertiesBean config;

	private final Locale localeThatHasAFile = new Locale("en");

	private final Locale localeThatDoesNotHaveAFile = new Locale("xx");

	@Before
	public void setup() {
		//test message files are located in test/resources/js/locale/
		Resource resource = new ClassPathResource("/resources/js/locale/");
		jsonMessageSource.setBaseDirectory(resource);
	}

	@Test
	public void verifyWhenLocaleExists_canResolveCode() {
		MessageFormat mf = jsonMessageSource.resolveCode("testAttribute", localeThatHasAFile);
		assertEquals(mf.getLocale().getLanguage(), "en");
		assertEquals(mf.toPattern(), "testValue");
	}

	@Test
	public void verifyWhenLocaleDoesNotExist_cannotResolveCode() {
		String code = "test";
		MessageFormat mf = jsonMessageSource.resolveCode("test", localeThatDoesNotHaveAFile);
		assertEquals(code, mf.toPattern());
	}
}
