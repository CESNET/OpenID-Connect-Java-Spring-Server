--
-- Indexes for MySQL
--

CREATE INDEX at_tv_idx ON access_token(token_value(767));
CREATE INDEX ts_oi_idx ON token_scope(owner_id);
CREATE INDEX at_exp_idx ON access_token(expiration);
CREATE INDEX rf_ahi_idx ON refresh_token(auth_holder_id);
CREATE INDEX rf_tv_idx ON refresh_token(token_value(105));
CREATE INDEX cd_ci_idx ON client_details(client_id);
CREATE INDEX at_ahi_idx ON access_token(auth_holder_id);
CREATE INDEX aha_oi_idx ON authentication_holder_authority(owner_id);
CREATE INDEX ahe_oi_idx ON authentication_holder_extension(owner_id);
CREATE INDEX ahrp_oi_idx ON authentication_holder_request_parameter(owner_id);
CREATE INDEX ahri_oi_idx ON authentication_holder_resource_id(owner_id);
CREATE INDEX ahrt_oi_idx ON authentication_holder_response_type(owner_id);
CREATE INDEX ahs_oi_idx ON authentication_holder_scope(owner_id);
CREATE INDEX ac_ahi_idx ON authorization_code(auth_holder_id);
CREATE INDEX suaa_oi_idx ON saved_user_auth_authority(owner_id);
CREATE INDEX access_token_client_id_index ON access_token (client_id);
CREATE INDEX access_token_refresh_token_id_index ON access_token (refresh_token_id);
CREATE INDEX approved_site_client_id_index ON approved_site (client_id);
CREATE INDEX approved_site_scope_owner_id_index ON approved_site_scope (owner_id);
CREATE INDEX authentication_holder_user_auth_id_index ON authentication_holder (user_auth_id);
CREATE INDEX authorization_code_code_index ON authorization_code (code);
CREATE INDEX client_authority_owner_id_index ON client_authority (owner_id);
CREATE INDEX client_claims_redirect_uri_owner_id_index ON client_claims_redirect_uri (owner_id);
CREATE INDEX client_contact_owner_id_index ON client_contact (owner_id);
CREATE INDEX client_default_acr_value_owner_id_index ON client_default_acr_value (owner_id);
CREATE INDEX client_grant_type_owner_id_index ON client_grant_type (owner_id);
CREATE INDEX client_post_logout_redirect_uri_owner_id_index ON client_post_logout_redirect_uri (owner_id);
CREATE INDEX client_redirect_uri_owner_id_index ON client_redirect_uri (owner_id);
CREATE INDEX client_request_uri_owner_id_index ON client_request_uri (owner_id);
CREATE INDEX client_resource_owner_id_index ON client_resource (owner_id);
CREATE INDEX client_response_type_owner_id_index ON client_response_type (owner_id);
CREATE INDEX client_scope_owner_id_index ON client_scope (owner_id);
CREATE INDEX device_code_auth_holder_id_index ON device_code (auth_holder_id);
CREATE INDEX device_code_device_code_index ON device_code (device_code);
CREATE INDEX device_code_user_code_index ON device_code (user_code);
CREATE INDEX device_code_request_parameter_owner_id_index ON device_code_request_parameter (owner_id);
CREATE INDEX device_code_scope_owner_id_index ON device_code_scope (owner_id);
CREATE INDEX refresh_token_token_value_index ON refresh_token (token_value);
CREATE INDEX whitelisted_site_scope_owner_id_index ON whitelisted_site_scope (owner_id);
