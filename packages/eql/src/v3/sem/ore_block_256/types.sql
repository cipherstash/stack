-- REQUIRE: src/v3/schema.sql

--! @file v3/sem/ore_block_256/types.sql
--! @brief ORE block index-term types ({{prefix}} SEM).
--!
--! Self-contained {{prefix}} copies of the Order-Revealing Encryption block types
--! (design D1/D3). The eql_v2 originals are unchanged.

--! @brief ORE block term type for Order-Revealing Encryption
--!
--! Composite type representing a single ORE block term. Stores encrypted data
--! as bytea that enables range comparisons without decryption.
CREATE TYPE {{prefix}}_internal.{{ore_block}}_term AS (
  bytes bytea
);


-- {{#v3}}
--! @brief ORE block index term type for range queries
--!
--! Composite type containing an array of ORE block terms. The array is stored
--! in the 'ob' field of encrypted data payloads.
--!
--! @note Transient type used only during query execution.
CREATE TYPE {{prefix}}_internal.{{ore_block}} AS (
  terms {{prefix}}_internal.{{ore_block}}_term[]
);
-- {{/v3}}
-- {{#v4}}
--! @brief ORE block index term type for range queries
--!
--! Composite type holding one ORE block term: the ore-rs ciphertext that
--! the 'ob' field of an encrypted payload stores as one hex string.
--!
--! @note Transient type used only during query execution.
CREATE TYPE {{prefix}}_internal.{{ore_block}} AS (
  term {{prefix}}_internal.{{ore_block}}_term
);
-- {{/v4}}
