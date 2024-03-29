/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package cz.muni.ics.oauth2.model.convert;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import org.springframework.util.StringUtils;

/**
 * @author jricher
 */
@Converter
public class JsonElementStringConverter implements AttributeConverter<JsonElement, String> {

	@Override
	public String convertToDatabaseColumn(JsonElement attribute) {
		return attribute != null ? attribute.toString() : null;
	}

	@Override
	public JsonElement convertToEntityAttribute(String dbData) {
		return StringUtils.hasText(dbData) ? JsonParser.parseString(dbData) : null;
	}

}
