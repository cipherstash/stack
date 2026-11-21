-- EQL v4 block ORE comparator timing harness. Loaded by run.sh into a
-- database with the EQL v4 bundle installed, after run.sh has created the
-- `ore_v2_timing` schema and loaded the ctgen output into
-- ore_v2_timing.staging (`\copy` cannot take a psql variable). Everything
-- lives in `ore_v2_timing`, which run.sh creates and drops afterwards.

SET search_path = ore_v2_timing, public;

CREATE FUNCTION term_of(h text)
  RETURNS eql_v4_internal.ore_block_v2_term[]
  LANGUAGE sql IMMUTABLE AS $$
  SELECT ARRAY[ROW(decode(h, 'hex'))::eql_v4_internal.ore_block_v2_term]
$$;

CREATE TABLE checks AS
  SELECT label::int AS expected, term_of(a_hex) AS a, term_of(b_hex) AS b
  FROM staging WHERE kind = 'check';

-- Timing pairs. Both classes of a kind share one table in random order, so
-- neither sits in a fixed region of memory: with separate per-class storage,
-- placement alone produced a timing difference in the ore.rs benches.
-- Class 1 is a difference in the first block. Class 0:
--   fixed, chained: a difference in the last block only;
--   equal:          a second encryption of the same value (no block differs);
--   prefix:         every block of the shorter term matches the longer's, so
--                   the block counts settle the order.
CREATE TABLE pairs AS
  SELECT kind, row_number() OVER (PARTITION BY kind ORDER BY random()) AS id,
         (label = 'first')::int AS cls, term_of(a_hex) AS a, term_of(b_hex) AS b
  FROM staging WHERE kind <> 'check';

-- dudect-style sampling. Each sample picks a class at random and times
-- `per_sample` comparisons of pairs of that class, each drawn at random with
-- replacement, through compare_ore_block_v2_terms over the composite (the
-- operator-class path). clock_timestamp() ticks in microseconds, so a sample
-- must span many of them.
CREATE FUNCTION bench(which_kind text, samples int, per_sample int)
  RETURNS TABLE (cls int, us double precision)
AS $$
DECLARE
  arrs_a eql_v4_internal.ore_block_v2[];
  arrs_b eql_v4_internal.ore_block_v2[];
  idx0 int[];
  idx1 int[];
  picks int[];
  c int;
  r int;
  t0 timestamptz;
  t1 timestamptz;
BEGIN
  SELECT array_agg(ROW(p.a)::eql_v4_internal.ore_block_v2 ORDER BY p.id),
         array_agg(ROW(p.b)::eql_v4_internal.ore_block_v2 ORDER BY p.id)
    INTO arrs_a, arrs_b FROM ore_v2_timing.pairs p WHERE p.kind = which_kind;
  SELECT array_agg(p.id::int ORDER BY p.id) FILTER (WHERE p.cls = 0),
         array_agg(p.id::int ORDER BY p.id) FILTER (WHERE p.cls = 1)
    INTO idx0, idx1 FROM ore_v2_timing.pairs p WHERE p.kind = which_kind;
  FOR s IN 1..samples LOOP
    c := (random() < 0.5)::int;
    IF c = 0 THEN
      picks := ARRAY(SELECT idx0[1 + floor(random() * cardinality(idx0))::int] FROM generate_series(1, per_sample));
    ELSE
      picks := ARRAY(SELECT idx1[1 + floor(random() * cardinality(idx1))::int] FROM generate_series(1, per_sample));
    END IF;
    t0 := clock_timestamp();
    FOREACH r IN ARRAY picks LOOP
      PERFORM eql_v4_internal.compare_ore_block_v2_terms(arrs_a[r], arrs_b[r]);
    END LOOP;
    t1 := clock_timestamp();
    cls := c;
    us := extract(epoch FROM t1 - t0) * 1e6;
    RETURN NEXT;
  END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Uncropped Welch t (every sample counts), with per-class mean and median.
-- Report this, not a percentile-cropped maximum: cropping turns a difference
-- in spread into a large t with no difference in mean.
CREATE FUNCTION welch(label text, tbl regclass)
  RETURNS TABLE (run text, n bigint, mean_0 numeric, mean_1 numeric,
                 median_0 numeric, median_1 numeric, t numeric)
AS $$
BEGIN
  RETURN QUERY EXECUTE format($q$
    WITH s AS (
      SELECT count(*) n,
             count(*) FILTER (WHERE cls = 0) n0, count(*) FILTER (WHERE cls = 1) n1,
             avg(us) FILTER (WHERE cls = 0) m0, avg(us) FILTER (WHERE cls = 1) m1,
             stddev(us) FILTER (WHERE cls = 0) s0, stddev(us) FILTER (WHERE cls = 1) s1,
             percentile_cont(0.5) WITHIN GROUP (ORDER BY us) FILTER (WHERE cls = 0) p0,
             percentile_cont(0.5) WITHIN GROUP (ORDER BY us) FILTER (WHERE cls = 1) p1
      FROM %s)
    SELECT %L::text, n, round(m0::numeric, 1), round(m1::numeric, 1),
           round(p0::numeric, 1), round(p1::numeric, 1),
           round(((m0 - m1) / sqrt(s0 * s0 / n0 + s1 * s1 / n1))::numeric, 2)
    FROM s$q$, tbl, label);
END;
$$ LANGUAGE plpgsql;
