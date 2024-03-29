--
-- Tables for OIDC Server functionality, PostgreSQL
--

CREATE TABLE IF NOT EXISTS access_token (
    id BIGSERIAL PRIMARY KEY,
    token_value VARCHAR(4096),
    expiration TIMESTAMP,
    token_type VARCHAR(256),
    refresh_token_id BIGINT,
    client_id BIGINT,
    auth_holder_id BIGINT,
    approved_site_id BIGINT,
    UNIQUE(token_value)
);

CREATE TABLE IF NOT EXISTS address (
    id BIGSERIAL PRIMARY KEY,
    formatted VARCHAR(256),
    street_address VARCHAR(256),
    locality VARCHAR(256),
    region VARCHAR(256),
    postal_code VARCHAR(256),
    country VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS approved_site (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(256),
    client_id VARCHAR(256),
    creation_date TIMESTAMP,
    access_date TIMESTAMP,
    timeout_date TIMESTAMP,
    whitelisted_site_id BIGINT
);

CREATE TABLE IF NOT EXISTS approved_site_scope (
    owner_id BIGINT,
    scope VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS authentication_holder (
    id BIGSERIAL PRIMARY KEY,
    user_auth_id BIGINT,
    approved BOOLEAN,
    redirect_uri VARCHAR(2048),
    client_id VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS authentication_holder_authority (
    owner_id BIGINT,
    authority VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS authentication_holder_resource_id (
    owner_id BIGINT,
    resource_id VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS authentication_holder_response_type (
    owner_id BIGINT,
    response_type VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS authentication_holder_extension (
    owner_id BIGINT,
    extension VARCHAR(2048),
    val VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS authentication_holder_scope (
    owner_id BIGINT,
    scope VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS authentication_holder_request_parameter (
    owner_id BIGINT,
    param VARCHAR(2048),
    val TEXT
);

CREATE TABLE IF NOT EXISTS saved_user_auth (
    id BIGSERIAL PRIMARY KEY,
    acr VARCHAR(1024),
    auth_time BIGINT DEFAULT NULL,
    name VARCHAR(1024),
    authenticated BOOLEAN,
    authentication_attributes TEXT
);

CREATE TABLE IF NOT EXISTS saved_user_auth_authority (
    owner_id BIGINT,
    authority VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS client_authority (
    owner_id BIGINT,
    authority VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS authorization_code (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(256),
    auth_holder_id BIGINT,
    expiration TIMESTAMP
);

CREATE TABLE IF NOT EXISTS client_grant_type (
    owner_id BIGINT,
    grant_type VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS client_response_type (
    owner_id BIGINT,
    response_type VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS blacklisted_site (
    id BIGSERIAL PRIMARY KEY,
    uri VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS client_details (
    id BIGSERIAL PRIMARY KEY,

    client_description VARCHAR(1024),
    reuse_refresh_tokens BOOLEAN DEFAULT true NOT NULL,
    dynamically_registered BOOLEAN DEFAULT false NOT NULL,
    allow_introspection BOOLEAN DEFAULT false NOT NULL,
    id_token_validity_seconds BIGINT DEFAULT 600 NOT NULL,
    device_code_validity_seconds BIGINT,

    client_id VARCHAR(256),
    client_secret VARCHAR(2048),
    access_token_validity_seconds BIGINT,
    refresh_token_validity_seconds BIGINT,

    application_type VARCHAR(256),
    client_name VARCHAR(256),
    token_endpoint_auth_method VARCHAR(256),
    subject_type VARCHAR(256),

    policy_uri VARCHAR(2048),
    client_uri VARCHAR(2048),
    tos_uri VARCHAR(2048),

    jwks_uri VARCHAR(2048),
    jwks VARCHAR(8192),
    sector_identifier_uri VARCHAR(2048),

    request_object_signing_alg VARCHAR(256),

    user_info_signed_response_alg VARCHAR(256),
    user_info_encrypted_response_alg VARCHAR(256),
    user_info_encrypted_response_enc VARCHAR(256),

    id_token_signed_response_alg VARCHAR(256),
    id_token_encrypted_response_alg VARCHAR(256),
    id_token_encrypted_response_enc VARCHAR(256),

    token_endpoint_auth_signing_alg VARCHAR(256),

    default_max_age BIGINT,
    require_auth_time BOOLEAN,
    created_at TIMESTAMP,
    initiate_login_uri VARCHAR(2048),
    clear_access_tokens_on_refresh BOOLEAN DEFAULT true NOT NULL,

    software_statement VARCHAR(4096),
    software_id VARCHAR(2048),
    software_version VARCHAR(2048),

    code_challenge_method VARCHAR(256),

    UNIQUE (client_id)
);

CREATE TABLE IF NOT EXISTS client_request_uri (
    owner_id BIGINT,
    request_uri VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS client_post_logout_redirect_uri (
    owner_id BIGINT,
    post_logout_redirect_uri VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS client_default_acr_value (
    owner_id BIGINT,
    default_acr_value VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS client_contact (
    owner_id BIGINT,
    contact VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS client_redirect_uri (
    owner_id BIGINT,
    redirect_uri VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS client_claims_redirect_uri (
    owner_id BIGINT,
    redirect_uri VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS refresh_token (
    id BIGSERIAL PRIMARY KEY,
    token_value VARCHAR(4096),
    expiration TIMESTAMP,
    auth_holder_id BIGINT,
    client_id BIGINT
);

CREATE TABLE IF NOT EXISTS client_resource (
    owner_id BIGINT,
    resource_id VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS client_scope (
    owner_id BIGINT,
    scope VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS token_scope (
    owner_id BIGINT,
    scope VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS system_scope (
    id BIGSERIAL PRIMARY KEY,
    scope VARCHAR(256) NOT NULL,
    description VARCHAR(4096),
    icon VARCHAR(256),
    restricted BOOLEAN DEFAULT false NOT NULL,
    default_scope BOOLEAN DEFAULT false NOT NULL,
    UNIQUE (scope)
);

CREATE TABLE IF NOT EXISTS user_info (
    id BIGSERIAL PRIMARY KEY,
    sub VARCHAR(256),
    preferred_username VARCHAR(256),
    name VARCHAR(256),
    given_name VARCHAR(256),
    family_name VARCHAR(256),
    middle_name VARCHAR(256),
    nickname VARCHAR(256),
    profile VARCHAR(256),
    picture VARCHAR(256),
    website VARCHAR(256),
    email VARCHAR(256),
    email_verified BOOLEAN,
    gender VARCHAR(256),
    zone_info VARCHAR(256),
    locale VARCHAR(256),
    phone_number VARCHAR(256),
    phone_number_verified BOOLEAN,
    address_id VARCHAR(256),
    updated_time VARCHAR(256),
    birthdate VARCHAR(256),
    src VARCHAR(4096)
);

CREATE TABLE IF NOT EXISTS whitelisted_site (
    id BIGSERIAL PRIMARY KEY,
    creator_user_id VARCHAR(256),
    client_id VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS whitelisted_site_scope (
    owner_id BIGINT,
    scope VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS pairwise_identifier (
    id BIGSERIAL PRIMARY KEY,
    identifier VARCHAR(256),
    sub VARCHAR(256),
    sector_identifier VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS device_code (
    id BIGSERIAL PRIMARY KEY,
    device_code VARCHAR(1024),
    user_code VARCHAR(1024),
    expiration TIMESTAMP NULL,
    client_id VARCHAR(256),
    approved BOOLEAN,
    auth_holder_id BIGINT
);

CREATE TABLE IF NOT EXISTS device_code_scope (
    owner_id BIGINT NOT NULL,
    scope VARCHAR(256) NOT NULL
);

CREATE TABLE IF NOT EXISTS device_code_request_parameter (
    owner_id BIGINT,
    param VARCHAR(2048),
    val VARCHAR(2048)
);

alter table access_token
    add constraint access_token_authentication_holder_id_fk
        foreign key (auth_holder_id) references authentication_holder (id)
            on update cascade on delete set null;

alter table access_token
    add constraint access_token_client_details_id_fk
        foreign key (client_id) references client_details (id)
            on update cascade on delete cascade;

alter table access_token
    add constraint access_token_refresh_token_id_fk
        foreign key (refresh_token_id) references refresh_token (id)
            on update cascade on delete set null;

alter table approved_site
    add constraint approved_site_client_details_id_fk
        foreign key (client_id) references client_details (client_id)
            on update cascade on delete cascade;

alter table approved_site_scope
    add constraint approved_site_scope_approved_site_id_fk
        foreign key (owner_id) references approved_site (id)
            on update cascade on delete cascade;

alter table authentication_holder_authority
    add constraint authentication_holder_authority_authentication_holder_id_fk
        foreign key (owner_id) references authentication_holder (id)
            on update cascade on delete cascade;

alter table authentication_holder_extension
    add constraint authentication_holder_extension_authentication_holder_id_fk
        foreign key (owner_id) references authentication_holder (id)
            on update cascade on delete cascade;

alter table authentication_holder_request_parameter
    add constraint auth_holder_request_parameter_authentication_holder_id_fk
        foreign key (owner_id) references authentication_holder (id)
            on update cascade on delete cascade;

alter table authentication_holder_resource_id
    add constraint authentication_holder_resource_id_authentication_holder_id_fk
        foreign key (owner_id) references authentication_holder (id)
            on update cascade on delete cascade;

alter table authentication_holder_response_type
    add constraint authentication_holder_response_type_authentication_holder_id_fk
        foreign key (owner_id) references authentication_holder (id)
            on update cascade on delete cascade;

alter table authentication_holder
    add constraint authentication_holder_saved_user_auth_id_fk
        foreign key (user_auth_id) references saved_user_auth (id)
            on update cascade on delete cascade;

alter table authentication_holder_scope
    add constraint authentication_holder_scope_authentication_holder_id_fk
        foreign key (owner_id) references authentication_holder (id)
            on update cascade on delete cascade;

alter table authorization_code
    add constraint authorization_code_authentication_holder_id_fk
        foreign key (auth_holder_id) references authentication_holder (id)
            on update cascade on delete cascade;

alter table client_authority
    add constraint client_authority_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_claims_redirect_uri
    add constraint client_claims_redirect_uri_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_contact
    add constraint client_contact_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_default_acr_value
    add constraint client_default_acr_value_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_grant_type
    add constraint client_grant_type_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_post_logout_redirect_uri
    add constraint client_post_logout_redirect_uri_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_redirect_uri
    add constraint client_redirect_uri_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_request_uri
    add constraint client_request_uri_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_resource
    add constraint client_resource_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_response_type
    add constraint client_response_type_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table client_scope
    add constraint client_scope_client_details_id_fk
        foreign key (owner_id) references client_details (id)
            on update cascade on delete cascade;

alter table device_code
    add constraint device_code_client_details_id_fk
        foreign key (client_id) references client_details (client_id)
            on update cascade on delete cascade;

alter table device_code
    add constraint device_code_authentication_holder_id_fk
        foreign key (auth_holder_id) references authentication_holder (id)
            on update cascade on delete set null;

alter table device_code_request_parameter
    add constraint device_code_request_parameter_device_code_id_fk
        foreign key (owner_id) references device_code (id)
            on update cascade on delete cascade;

alter table device_code_scope
    add constraint device_code_scope_device_code_id_fk
        foreign key (owner_id) references device_code (id)
            on update cascade on delete cascade;

alter table refresh_token
    add constraint refresh_token_authentication_holder_id_fk
        foreign key (auth_holder_id) references authentication_holder (id)
            on update cascade on delete set null;

alter table refresh_token
    add constraint refresh_token_client_details_id_fk
        foreign key (client_id) references client_details (id)
            on update cascade on delete cascade;

alter table saved_user_auth_authority
    add constraint saved_user_auth_authority_saved_user_auth_id_fk
        foreign key (owner_id) references saved_user_auth (id)
            on update cascade on delete cascade;

alter table token_scope
    add constraint token_scope_refresh_token_id_fk
        foreign key (owner_id) references access_token (id)
            on update cascade on delete cascade;

alter table whitelisted_site
    add constraint whitelisted_site_client_details_id_fk
        foreign key (client_id) references client_details (client_id)
            on update cascade on delete cascade;

alter table whitelisted_site_scope
    add constraint whitelisted_site_scope_whitelisted_site_id_fk
        foreign key (owner_id) references whitelisted_site (id)
            on update cascade on delete cascade;
