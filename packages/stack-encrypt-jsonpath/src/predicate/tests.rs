use super::*;

/// The tree written out: each comparison as `path op value`, a literal as
/// its text and a variable as `$name`.
fn written(text: &str, expression: &Expression) -> String {
    let list = |terms: &[Expression]| {
        terms
            .iter()
            .map(|term| written(text, term))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match expression {
        Expression::And(terms) => format!("and({})", list(terms)),
        Expression::Or(terms) => format!("or({})", list(terms)),
        Expression::Not(term) => format!("not({})", written(text, term)),
        Expression::Compare(comparison) => compared(text, comparison),
        Expression::Exists { path, filter: None } => format!("exists({})", path.path),
        Expression::Exists {
            path,
            filter: Some(conditions),
        } => format!(
            "exists({} ? {})",
            path.path,
            conditions
                .iter()
                .map(|condition| compared(text, condition))
                .collect::<Vec<_>>()
                .join(" && ")
        ),
    }
}

fn compared(text: &str, comparison: &Comparison) -> String {
    let value = match &comparison.value {
        ValueAt::Literal { start, end } => text[*start..*end].to_owned(),
        ValueAt::Variable { name, .. } => format!("${}", name.as_str()),
    };
    format!(
        "{} {:?}@{} {value}",
        comparison.path.path, comparison.operator, comparison.at
    )
}

fn parses_to(text: &str, want: &str) {
    let expression = parse(text).unwrap_or_else(|error| panic!("{text}: {error}"));
    assert_eq!(written(text, &expression), want, "{text}");
}

fn refused(text: &str) -> (PredicateErrorKind, &'static str, usize) {
    match parse(text) {
        Err(error) => (error.kind, error.construct, error.at),
        Ok(expression) => panic!("{text}: parsed to {}", written(text, &expression)),
    }
}

mod given_the_grammar_it_reads {
    use super::*;

    /// Each operator is read, a value on the left turns the comparison
    /// round, and `<>` is `!=`.
    #[test]
    fn reads_each_operator_either_way_round() {
        for (text, want) in [
            ("$.a == 1", "$.a Equal@4 1"),
            ("$.a != 1", "$.a NotEqual@4 1"),
            ("$.a <> 1", "$.a NotEqual@4 1"),
            ("$.a < 1", "$.a Less@4 1"),
            ("$.a <= 1", "$.a LessOrEqual@4 1"),
            ("$.a > 1", "$.a Greater@4 1"),
            ("$.a >= 1", "$.a GreaterOrEqual@4 1"),
            ("1 < $.a", "$.a Greater@2 1"),
            ("1 <= $.a", "$.a GreaterOrEqual@2 1"),
            ("1 > $.a", "$.a Less@2 1"),
            ("1 >= $.a", "$.a LessOrEqual@2 1"),
            ("1 == $.a", "$.a Equal@2 1"),
            ("1 != $.a", "$.a NotEqual@2 1"),
        ] {
            parses_to(text, want);
        }
    }

    /// Literals, variables (bare and quoted), quoted keys, keys that are
    /// words of the grammar, space and comments read as PostgreSQL reads
    /// them.
    #[test]
    fn reads_values_and_paths_as_postgres_reads_them() {
        for (text, want) in [
            (r#"$.name == "Ann""#, r#"$.name Equal@7 "Ann""#),
            ("$.ok == true", "$.ok Equal@5 true"),
            ("$.ok == false", "$.ok Equal@5 false"),
            ("$.gone == null", "$.gone Equal@7 null"),
            ("$.a == -1.5e3", "$.a Equal@4 -1.5e3"),
            ("$.a == 10.125E+2", "$.a Equal@4 10.125E+2"),
            ("$.a == 0", "$.a Equal@4 0"),
            ("$.a == $min", "$.a Equal@4 $min"),
            (r#"$.a == $"first name""#, "$.a Equal@4 $first name"),
            (r#"$."first name" == 1"#, "$.first name Equal@15 1"),
            (r#"$.  "a b".c == 1"#, "$.a b.c Equal@12 1"),
            (r#"$."a\"b" == 1"#, r#"$["a\"b"] Equal@9 1"#),
            ("$.exists == 1", "$.exists Equal@9 1"),
            ("$.true == 1", "$.true Equal@7 1"),
            ("$ . a [ * ] . b == 1", "$.a[*].b Equal@16 1"),
            ("  $.a==1  ", "$.a Equal@5 1"),
            ("$.a == 1 /* why */", "$.a Equal@4 1"),
            ("/* a */ $.a == 1", "$.a Equal@12 1"),
            ("$ == 1", "$ Equal@2 1"),
            ("$.a == 1 && $.b == 2", "and($.a Equal@4 1, $.b Equal@16 2)"),
        ] {
            parses_to(text, want);
        }
    }

    /// `&&` binds tighter than `||`, parentheses group, `!` takes a group
    /// or `exists`, and `exists` is read in any case, with or without a
    /// filter.
    #[test]
    fn keeps_the_boolean_structure() {
        for (text, want) in [
            (
                "$.a == 1 && $.b == 2 || $.c == 3",
                "or(and($.a Equal@4 1, $.b Equal@16 2), $.c Equal@28 3)",
            ),
            (
                "$.a == 1 && ($.b == 2 || $.c == 3)",
                "and($.a Equal@4 1, or($.b Equal@17 2, $.c Equal@29 3))",
            ),
            ("!($.a == 1)", "not($.a Equal@6 1)"),
            ("! exists($.a)", "not(exists($.a))"),
            ("((($.a == 1)))", "$.a Equal@7 1"),
            ("EXISTS($.a) || Exists($.b)", "or(exists($.a), exists($.b))"),
            (
                "exists($.c[*] ? (@.r == $r && @.n > 5))",
                "exists($.c[*] ? $.r Equal@21 $r && $.n Greater@34 5)",
            ),
            (
                "exists($.c[*] ? ((@.n >= 1) && (@.n < 9)))",
                "exists($.c[*] ? $.n GreaterOrEqual@22 1 && $.n Less@36 9)",
            ),
            ("exists($.t[*] ? (1 == @))", "exists($.t[*] ? $ Equal@19 1)"),
        ] {
            parses_to(text, want);
        }
    }

    /// The nesting limit is read, and nesting is depth, not count.
    #[test]
    fn reads_nesting_up_to_the_limit() {
        let at_limit = format!(
            "{}$.a == 1{}",
            "(".repeat(MAX_NESTING),
            ")".repeat(MAX_NESTING)
        );
        assert!(parse(&at_limit).is_ok());
        for sibling in ["($.a == 1)", "!($.a == 1)", "exists($.a)"] {
            let wide = vec![sibling; MAX_NESTING + 1].join(" && ");
            assert!(parse(&wide).is_ok(), "{sibling} side by side");
        }
        let deepest = format!("$.{} == 1", vec!["a"; MAX_DEPTH].join("."));
        assert!(parse(&deepest).is_ok(), "a path as deep as a document");
    }

    /// A literal's kind and text are read from the predicate; a variable
    /// has neither, and gives its name.
    #[test]
    fn a_value_says_what_it_is() {
        let text =
            r#"$.a == "x" || $.a == 2 || $.a == true || $.a == false || $.a == null || $.a == $v"#;
        let Expression::Or(terms) = parse(text).unwrap() else {
            panic!("an or")
        };
        // Each value's kind, literal text, variable name and offset.
        type Read<'t> = (Option<LiteralKind>, Option<&'t str>, Option<&'t str>, usize);
        let values: Vec<Read<'_>> = terms
            .iter()
            .map(|term| match term {
                Expression::Compare(comparison) => (
                    comparison.value.literal_kind(text),
                    comparison.value.literal_text(text),
                    comparison.value.variable(),
                    comparison.value.at(),
                ),
                _ => panic!("a comparison"),
            })
            .collect();
        assert_eq!(
            values,
            [
                (Some(LiteralKind::String), Some(r#""x""#), None, 7),
                (Some(LiteralKind::Number), Some("2"), None, 21),
                (Some(LiteralKind::Boolean), Some("true"), None, 33),
                (Some(LiteralKind::Boolean), Some("false"), None, 48),
                (Some(LiteralKind::Null), Some("null"), None, 64),
                (None, None, Some("v"), 79),
            ]
        );
        assert_eq!(
            ValueAt::Literal { start: 7, end: 9 }.literal_kind("$.a == -1"),
            Some(LiteralKind::Number)
        );
    }

    #[test]
    fn an_operator_flips_to_the_one_with_its_operands_swapped() {
        for (operator, flipped) in [
            (Operator::Equal, Operator::Equal),
            (Operator::NotEqual, Operator::NotEqual),
            (Operator::Less, Operator::Greater),
            (Operator::LessOrEqual, Operator::GreaterOrEqual),
            (Operator::Greater, Operator::Less),
            (Operator::GreaterOrEqual, Operator::LessOrEqual),
        ] {
            assert_eq!(operator.flipped(), flipped);
        }
    }
}

mod given_text_it_refuses {
    use super::*;

    use PredicateErrorKind::{Position, Syntax, TooDeep, Unsupported};

    /// Each construct the index cannot answer is refused by name, at the
    /// byte where it starts.
    #[test]
    fn names_each_unsupported_construct_at_its_offset() {
        use construct::*;
        for (text, construct, at) in [
            ("strict $.a == 1", MODE, 0),
            ("STRICT $.a == 1", MODE, 0),
            ("  lax $.a == 1", MODE, 2),
            ("$.a == Lax", MODE, 7),
            ("$.a == lax", MODE, 7),
            (r#"$.a LIKE_REGEX "x""#, LIKE_REGEX, 4),
            (r#"$.a like_regex "x""#, LIKE_REGEX, 4),
            (r#"$.a Starts with "x""#, STARTS_WITH, 4),
            ("$.a IS unknown", IS_UNKNOWN, 4),
            ("$.a[LAST] == 1", LAST, 3),
            ("$.a == LAST", LAST, 7),
            ("$.a[last] == 1", LAST, 3),
            (r#"exists($.a like_regex "x")"#, LIKE_REGEX, 11),
            ("exists($.a + 1)", ARITHMETIC, 11),
            (
                "exists($.a[*] ? (@ == 1) starts with \"x\")",
                STARTS_WITH,
                25,
            ),
            ("$.a + 1 == 2", ARITHMETIC, 4),
            ("$.a == 1 - 2", ARITHMETIC, 9),
            ("$.a == 1 * 2", ARITHMETIC, 9),
            ("$.a == 1 / 2", ARITHMETIC, 9),
            ("$.a == 1 % 2", ARITHMETIC, 9),
            ("$.a == +1", ARITHMETIC, 7),
            ("$.a.size() == 1", METHOD, 3),
            ("$.a.type () == 1", METHOD, 3),
            ("$.* == 1", ANY_MEMBER, 1),
            ("$.** == 1", ANY_DEPTH, 1),
            ("$. * == 1", ANY_MEMBER, 1),
            ("$.a[1 to 2] == 1", SLICE, 3),
            ("$.a[1, 2] == 1", SLICE, 3),
            ("$.a[$i] == 1", SUBSCRIPT, 3),
            ("@ == 1", AT_OUTSIDE, 0),
            ("$.a == $.b", TWO_PATHS, 4),
            ("1 == 1", TWO_VALUES, 2),
            ("$x == $y", TWO_VALUES, 3),
            ("$.a", ALONE, 3),
            ("$.a && $.b == 1", ALONE, 4),
            ("($.a)", ALONE, 4),
            ("$.a || $.b == 1", ALONE, 4),
            ("true", ALONE, 4),
            ("$.a[*] ? (@ == 1) == 1", FILTER_OUTSIDE, 7),
            ("exists($.a[*] ? (@ == 1).b)", AFTER_FILTER, 24),
            ("exists($.a[*] ? (@ == 1)[*])", AFTER_FILTER, 24),
            ("exists($.a[*] ? (@ == 1) ? (@ == 2))", FILTER_OUTSIDE, 24),
            ("exists($.a ?(@ == 1) ? (@ == 2))", FILTER_OUTSIDE, 20),
            ("exists($.a == 1)", IN_EXISTS, 7),
            ("exists(@)", AT_OUTSIDE, 7),
            ("exists($.a[*] ? (@.b == 1 || @.c == 2))", OR_IN_FILTER, 26),
            ("exists($.a[*] ? (!(@.b == 1)))", NOT_IN_FILTER, 17),
            ("exists($.a[*] ? (@.b != 1))", NOT_EQUAL_IN_FILTER, 21),
            ("exists($.a[*] ? (exists(@.b)))", EXISTS_IN_FILTER, 17),
            ("exists($.a[*] ? ($.b == 1))", DOLLAR_IN_FILTER, 17),
            ("$.v == $x.y", VARIABLE_PATH, 9),
            ("$.v == $x[0]", VARIABLE_PATH, 9),
        ] {
            assert_eq!(refused(text), (Unsupported, construct, at), "{text}");
        }
    }

    /// Text that is not a predicate is refused where reading stops.
    #[test]
    fn refuses_text_that_is_not_a_predicate_where_reading_stops() {
        use construct::*;
        for (text, construct, at) in [
            ("", TEXT, 0),
            ("   ", TEXT, 3),
            ("$.a == 1 &&", TEXT, 11),
            ("$.a = 1", TEXT, 4),
            ("$.a === 1", TEXT, 6),
            ("$.a > 1 > 2", TRAILING, 8),
            ("$.a == 1 2", TRAILING, 9),
            ("($.a == 1) is unknown", TRAILING, 11),
            ("!$.a == 1", TEXT, 1),
            ("!!($.a == 1)", TEXT, 1),
            ("($.a == 1", TEXT, 9),
            ("$.a == 01", NUMBER, 7),
            ("$.a == 1.", NUMBER, 7),
            ("$.a == 1e", NUMBER, 7),
            ("$.a == 1e+", NUMBER, 7),
            ("$.a == 1x", NUMBER, 7),
            ("$.a == 1.5.2", NUMBER, 7),
            ("$.a == -", NUMBER, 7),
            ("$.a == .5", TEXT, 7),
            ("$.a == 'x'", TEXT, 7),
            (r#"$.a == "x"#, STRING, 7),
            (r#"$.a == "\x41""#, STRING, 7),
            (r#"$."a == 1"#, STRING, 2),
            (r#"$.a == $"x"#, STRING, 8),
            ("$.a == TRUE", TEXT, 7),
            ("$.1a == 1", TEXT, 2),
            ("$. == 1", TEXT, 3),
            ("$.a[*", TEXT, 5),
            ("$.a == 1 /* open", TEXT, 9),
            ("exists $.a", TEXT, 7),
            ("exists($.a", TEXT, 10),
            ("exists(1)", TEXT, 7),
            ("exists($.a[*] ? @.b == 1)", TEXT, 16),
            ("exists($.a[*] ? (@.b == 1)", TEXT, 26),
            ("$.a == $1", TEXT, 8),
            ("$.a ==", TEXT, 6),
        ] {
            assert_eq!(refused(text), (Syntax, construct, at), "{text}");
        }
    }

    /// A position, nesting past the limit and a path past a document's
    /// depth are refused by their own kinds.
    #[test]
    fn refuses_positions_and_depth() {
        let deep = format!(
            "{} $.a == 1{}",
            "(".repeat(MAX_NESTING + 1),
            ")".repeat(MAX_NESTING + 1)
        );
        let negations = format!(
            "{}($.a == 1){}",
            "!(".repeat(MAX_NESTING),
            ")".repeat(MAX_NESTING)
        );
        let long = format!("$.{} == 1", vec!["a"; MAX_DEPTH + 1].join("."));
        let past = format!("$.{}.** == 1", vec!["a"; MAX_DEPTH].join("."));
        for (text, want) in [
            ("$.a[2] == 1", (Position, construct::POSITION, 3)),
            ("exists($.a[ 0 ])", (Position, construct::POSITION, 10)),
            (
                deep.as_str(),
                (TooDeep, construct::NESTING, MAX_NESTING + 1),
            ),
            (long.as_str(), (TooDeep, construct::NESTING, 0)),
            (past.as_str(), (TooDeep, construct::NESTING, 0)),
        ] {
            assert_eq!(refused(text), want, "{text}");
        }
        assert_eq!(refused(&negations).0, TooDeep);
    }

    /// A refusal displays its construct and offset, and nothing of the
    /// text.
    #[test]
    fn a_refusal_quotes_no_text_of_the_predicate() {
        let secret = "zq-secret-key-name";
        for text in [
            format!(r#"$."{secret}" like_regex "x""#),
            format!(r#"$.{secret} == "{secret}" + 1"#),
            format!(r#"$.{secret} == "{secret}" {secret}"#),
        ] {
            let error = parse(&text).unwrap_err();
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains(secret), "{shown}");
        }
        assert_eq!(
            parse("$.a like_regex \"x\"").unwrap_err().to_string(),
            "`like_regex` at byte 4"
        );
    }
}

mod given_a_structure_the_index_cannot_answer {
    use super::*;

    fn comparison(text: &str) -> Comparison {
        match parse(text).unwrap() {
            Expression::Compare(comparison) => comparison,
            other => panic!("{text}: {other:?}"),
        }
    }

    fn filter(text: &str) -> (PathAt, Vec<Comparison>) {
        match parse(text).unwrap() {
            Expression::Exists {
                path,
                filter: Some(conditions),
            } => (path, conditions),
            other => panic!("{text}: {other:?}"),
        }
    }

    /// `!=` is refused at a wildcard and read at one node; every other
    /// operator is read at both.
    #[test]
    fn refuses_not_equal_at_a_wildcard_only() {
        let refusal = comparison("$.a[*].b != 1")
            .refuse_not_equal_at_wildcard()
            .unwrap_err();
        assert_eq!(
            (refusal.kind, refusal.construct, refusal.at),
            (
                PredicateErrorKind::NotEqualAtWildcard,
                construct::NOT_EQUAL,
                9
            )
        );
        for text in ["$.a != 1", "$.a[*] == 1", "$.a[*].b > 1"] {
            assert!(
                comparison(text).refuse_not_equal_at_wildcard().is_ok(),
                "{text}"
            );
        }
    }

    /// An ordering at a wildcard splits at the last wildcard, and is refused
    /// when nothing follows it.
    #[test]
    fn an_ordering_at_a_wildcard_names_a_member() {
        let (base, member) = comparison("$.a[*].b[*].c.d > 1")
            .path
            .element_member(16)
            .unwrap();
        assert_eq!(
            (base.to_string(), member.to_string()),
            ("$.a[*].b[*]".to_owned(), "$.c.d".to_owned())
        );
        let refusal = comparison("$.a[*] > 1").path.element_member(7).unwrap_err();
        assert_eq!(
            (refusal.kind, refusal.construct, refusal.at),
            (
                PredicateErrorKind::Unsupported,
                construct::ELEMENTS_THEMSELVES,
                7
            )
        );
    }

    /// A filter needs a wildcard on its path and none in its members, and
    /// no member deeper than a document.
    #[test]
    fn a_filter_is_on_elements_and_names_their_members() {
        let (path, conditions) = filter("exists($.a[*] ? (@.b == 1 && @.c > 2))");
        assert!(check_filter(&path, &conditions).is_ok());
        for (text, want) in [
            (
                "exists($.a ? (@ == 1))",
                (
                    PredicateErrorKind::FilterWithoutWildcard,
                    construct::FILTER_WILDCARD,
                    7,
                ),
            ),
            (
                "exists($.a[*] ? (@.b == 1 && @.c[*] == 1))",
                (
                    PredicateErrorKind::MemberWildcard,
                    construct::MEMBER_WILDCARD,
                    29,
                ),
            ),
        ] {
            let (path, conditions) = filter(text);
            let refusal = check_filter(&path, &conditions).unwrap_err();
            assert_eq!(
                (refusal.kind, refusal.construct, refusal.at),
                want,
                "{text}"
            );
        }
        let member =
            |steps: usize| format!("exists($.a[*] ? (@.{} == 1))", vec!["b"; steps].join("."));
        let (path, conditions) = filter(&member(MAX_DEPTH - 2));
        assert!(
            check_filter(&path, &conditions).is_ok(),
            "as deep as a document"
        );
        let (path, conditions) = filter(&member(MAX_DEPTH - 1));
        let refusal = check_filter(&path, &conditions).unwrap_err();
        assert_eq!(
            (refusal.kind, refusal.at),
            (PredicateErrorKind::TooDeep, 7),
            "deeper than a document"
        );
    }

    /// One equality is containment; anything else is an element-scoped
    /// predicate, whose conditions each name a member.
    #[test]
    fn a_filter_condition_names_a_member() {
        let (_, one) = filter("exists($.a[*] ? (@.b == 1))");
        assert!(single_equality(&one).is_some());
        let (_, ordering) = filter("exists($.a[*] ? (@.b > 1))");
        assert!(single_equality(&ordering).is_none());
        let (_, two) = filter("exists($.a[*] ? (@.b == 1 && @.c == 2))");
        assert!(single_equality(&two).is_none());
        for condition in &two {
            assert!(condition.check_filter_condition().is_ok());
        }
        for (text, construct, at) in [
            (
                "exists($.a[*] ? (@ == 1 && @.c < 2))",
                construct::WHOLE_ELEMENT,
                17,
            ),
            (
                "exists($.a[*] ? (@ > 1 && @.c < 2))",
                construct::ELEMENTS_THEMSELVES,
                17,
            ),
        ] {
            let (_, conditions) = filter(text);
            let refusal = conditions[0].check_filter_condition().unwrap_err();
            assert_eq!(
                (refusal.kind, refusal.construct, refusal.at),
                (PredicateErrorKind::Unsupported, construct, at),
                "{text}"
            );
        }
        // `!=` never reaches a filter from the parser; a comparison built
        // with it is refused at its operator all the same.
        let not_equal = Comparison {
            path: PathAt {
                path: JsonPath::parse("$.b").unwrap(),
                at: 0,
            },
            operator: Operator::NotEqual,
            value: ValueAt::Literal { start: 0, end: 1 },
            at: 4,
        };
        let refusal = not_equal.check_filter_condition().unwrap_err();
        assert_eq!(
            (refusal.construct, refusal.at),
            (construct::NOT_EQUAL_IN_FILTER, 4)
        );
    }
}
