# SQL Documentation (Doxygen) — Contributor Reference

> The authoritative rules live in `CLAUDE.md` ("Documentation Standards"). This file is
> the longer-form contributor reference: the tag requirements, worked `eql_v3` examples,
> and copy-paste templates. When the two disagree, `CLAUDE.md` wins.

All SQL functions and types are documented with Doxygen-style comments using the `--!`
prefix (not plain `--`). Coverage and required tags are checked by `mise run docs:validate`.

## Required / Encouraged / Optional tags

### Mandatory
- `@brief` - one-sentence description
- `@param` - For each parameter (with type and description)
- `@return` - Return value description (include structure for JSONB)

### Encouraged
- `@example` - Usage examples (SQL code blocks)
- `@throws` - Exception conditions (when RAISE is used)
- `@internal` - Mark private functions (prefix with `_`)

### Optional
- `@see` - Cross-references
- `@note` - Additional warnings/notes
- `@deprecated` - Migration path for deprecated functions

## Worked examples (`eql_v3`)

### Public Function
```sql
--! @brief Extract the equality (hm) index term from an encrypted value
--!
--! Returns the HMAC equality term used by `=` / `<>` and by a functional
--! hash index. Inlinable, so a functional index on this extractor engages
--! bare-form queries.
--!
--! @param a public.eql_v3_integer_eq Encrypted value carrying an `hm` term
--! @return eql_v3_internal.hmac_256 The equality index term
--!
--! @example
--! CREATE INDEX ON users USING hash (eql_v3.eq_term(salary_eq));
--!
--! @see eql_v3.ord_term
CREATE FUNCTION eql_v3.eq_term(a public.eql_v3_integer_eq)
  RETURNS eql_v3_internal.hmac_256
AS $$ ... $$;
```

### Private Function
```sql
--! @brief Internal helper for encrypted-payload validation
--! @internal
--! @param val JSONB Encrypted payload to validate
--! @return Boolean True if the payload is well-formed
CREATE FUNCTION eql_v3._validate_payload(val jsonb)
  RETURNS boolean
AS $$ ... $$;
```

### Operator
```sql
--! @brief Equality comparison for an encrypted-domain value
--!
--! Implements the `=` operator for an `eql_v3` domain variant. Reduces to a
--! comparison on the extracted equality term — no decryption.
--!
--! @param a public.eql_v3_integer_eq Left operand
--! @param b public.eql_v3_integer_eq Right operand
--! @return Boolean True if the equality terms match
--!
--! @example
--! -- Using operator syntax:
--! SELECT * FROM users WHERE encrypted_email = $1;
--!
--! @see eql_v3.eq_term
CREATE FUNCTION eql_v3.eq(a public.eql_v3_integer_eq, b public.eql_v3_integer_eq)
  RETURNS boolean
AS $$ ... $$;

CREATE OPERATOR = (
  FUNCTION=eql_v3.eq,
  LEFTARG=public.eql_v3_integer_eq,
  RIGHTARG=public.eql_v3_integer_eq
);
```

### Domain Type
```sql
--! @brief Encrypted-domain type for an equality-searchable integer column
--!
--! A `jsonb`-backed domain in the `public` schema. The `CHECK` requires the
--! envelope keys (`v`, `i`, `c`), the equality term (`hm`), and pins the
--! payload version (`VALUE->>'v' = '3'`).
--!
--! @see eql_v3.eq_term
CREATE DOMAIN public.eql_v3_integer_eq AS jsonb
  CHECK ( ... );
```

### Aggregate
```sql
--! @brief State transition function for the MIN aggregate
--! @internal
--! @param $1 public.eql_v3_integer_ord Accumulated state
--! @param $2 public.eql_v3_integer_ord New value
--! @return public.eql_v3_integer_ord Updated state
CREATE FUNCTION eql_v3_internal.min_sfunc(public.eql_v3_integer_ord, public.eql_v3_integer_ord)
  RETURNS public.eql_v3_integer_ord
AS $$ ... $$;

--! @brief Minimum encrypted value in a group
--!
--! Aggregate over an ordered encrypted-domain column. Comparison routes
--! through the variant's `<` operator (the ORE block term) — no decryption.
--!
--! @param input public.eql_v3_integer_ord Encrypted values to aggregate
--! @return public.eql_v3_integer_ord The minimum value
--!
--! @example
--! SELECT eql_v3.min(price_encrypted) FROM products;
--!
--! @see eql_v3_internal.min_sfunc
CREATE AGGREGATE eql_v3.min(public.eql_v3_integer_ord) (
  SFUNC = eql_v3_internal.min_sfunc,
  STYPE = public.eql_v3_integer_ord,
  COMBINEFUNC = eql_v3_internal.min_sfunc,
  PARALLEL = safe
);
```

## Copy-paste templates

### Template: Public Function
```sql
--! @brief [One sentence description]
--!
--! [Detailed description paragraph explaining purpose,
--! behavior, and any important context]
--!
--! @param param_name [Type] [Description]
--! @param param_name [Type] [Description with default: DEFAULT value]
--! @return [Return type] [Description of return value structure]
--! @throws [Condition that triggers exception]
--!
--! @example
--! -- [Example description]
--! SELECT eql_v3.function_name('value1', 'value2');
--!
--! @see eql_v3.related_function
CREATE FUNCTION eql_v3.function_name(...)
```

### Template: Private/Internal Function
```sql
--! @brief [One sentence description]
--! @internal
--! @param param_name [Type] [Description]
--! @return [Return type] [Description]
CREATE FUNCTION eql_v3._internal_function(...)
```

### Template: Operator Implementation
```sql
--! @brief [Operator symbol] operator for encrypted values
--!
--! Implements the [operator] operator using [index type] for
--! [operation description] without decryption.
--!
--! @param a eql_v3.[domain_type] Left operand
--! @param b eql_v3.[domain_type] Right operand
--! @return Boolean [Result description]
--!
--! @example
--! -- [Specific example showing operator usage]
--! SELECT * FROM table WHERE encrypted_col [operator] value;
--!
--! @see eql_v3.[related_function]
CREATE FUNCTION eql_v3."[operator]"(...)
```

### Template: Domain Type
```sql
--! @brief [Type name] index term type
--!
--! Domain type representing [description of what this type represents].
--! Used for [use case] during searchable-encryption queries (e.g. equality via
--! `eq_term`, ordering via `ord_term`).
--!
--! @see eql_v3.eq_term
--! @note This is a transient type used only during query execution
--! @note SEM index-term types live in `eql_v3_internal` and are backed by whatever
--!   base type the term needs (`hmac_256 AS text`, `ope_cllw AS bytea`) — never
--!   domain-over-domain. (Encrypted-domain *column* types are the jsonb-backed
--!   `public.eql_v3_*` domains.)
CREATE DOMAIN eql_v3_internal.[type_name] AS [base_type];
```

### Template: Aggregate Function
```sql
--! @brief [State function description]
--! @internal
--! @param $1 [State type] [State description]
--! @param $2 [Input type] [Input description]
--! @return [State type] [Updated state description]
CREATE FUNCTION eql_v3._state_function(...)

--! @brief [Aggregate behavior description]
--!
--! [Detailed description of what aggregate computes]
--!
--! @param input [Input type] [Input description]
--! @return [Return type] [Return description]
--!
--! @example
--! -- [Example query using aggregate]
--!
--! @see eql_v3._state_function
CREATE AGGREGATE eql_v3.aggregate_name(...) (...)
```

### Template: Constraint Function
```sql
--! @brief [Constraint check description]
--!
--! [What the constraint validates]
--!
--! @param value [Type] [Value being checked]
--! @return Boolean True if constraint satisfied
--! @throws Exception if [constraint violation condition]
CREATE FUNCTION eql_v3.[constraint_function](...)
```
