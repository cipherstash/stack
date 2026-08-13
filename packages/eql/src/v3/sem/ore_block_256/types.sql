-- REQUIRE: src/v3/schema.sql

--! @file v3/sem/ore_block_256/types.sql
--! @brief ORE block index-term types (eql_v3 SEM).
--!
--! Self-contained eql_v3 copies of the Order-Revealing Encryption block types
--! (design D1/D3). The eql_v2 originals are unchanged.

--! @brief ORE block term type for Order-Revealing Encryption
--!
--! Composite type representing a single ORE block term. Stores encrypted data
--! as bytea that enables range comparisons without decryption.
CREATE TYPE eql_v3_internal.ore_block_256_term AS (
  bytes bytea
);


--! @brief ORE block index term type for range queries
--!
--! Composite type containing an array of ORE block terms. The array is stored
--! in the 'ob' field of encrypted data payloads.
--!
--! @note Transient type used only during query execution.
CREATE TYPE eql_v3_internal.ore_block_256 AS (
  terms eql_v3_internal.ore_block_256_term[]
);
