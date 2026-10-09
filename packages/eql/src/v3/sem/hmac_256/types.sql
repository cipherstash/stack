-- REQUIRE: src/v3/schema.sql

--! @file v3/sem/hmac_256/types.sql
--! @brief HMAC-SHA256 index term type ({{prefix}} SEM)
--!
--! Domain type representing HMAC-SHA256 hash values. Used for exact-match
--! encrypted searches. The hash is stored in the 'hm' field of encrypted data
--! payloads. Self-contained {{prefix}} copy (design D1/D3); the eql_v2 original is
--! unchanged.
--!
--! @note Transient type used only during query execution.
CREATE DOMAIN {{prefix}}_internal.hmac_256 AS text;
