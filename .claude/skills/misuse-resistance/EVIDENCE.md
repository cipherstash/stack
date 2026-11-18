# Evidence

The studies behind each rule in [SKILL.md](SKILL.md). Cite these when a rule is challenged in review. Fuller notes, with the source of each figure, are in the vitaminc repository at `docs/research/misuse-resistance.md`.

## Why the API carries the burden

- **Lazar et al. 2014**, *Why does cryptographic software fail?* (APSys). Of 269 crypto CVEs, 83% were applications misusing libraries; 17% were in the libraries. The sample is CVEs tagged CWE-310 (cryptographic issues), so library bugs filed under other weakness classes are outside the count.
- **Oliveira et al. 2014**, *It's the psychology stupid* (ACSAC). Security is not part of developers' everyday heuristics. Primed developers found about twice as many vulnerabilities.
- **Acar et al. 2016**, *You get where you're looking for* (IEEE S&P). Developers using Stack Overflow produced the most functional and least secure code, and rated insecure solutions as secure.
- **Perry et al. 2023**, *Do users write more insecure code with AI assistants?* (CCS). Participants with an AI assistant wrote less secure code, including for encryption, and were more confident it was secure.
- **Elsayed et al. 2026**, *An empirical security evaluation of LLM-generated cryptographic Rust code* (arXiv:2604.27001). 23.3% of 240 samples compiled; of those, 57% had vulnerabilities, chiefly nonce reuse and hallucinated APIs.
- **Blessing et al. 2021** (arXiv:2107.04940). In eight C/C++ libraries, 37.2% of vulnerabilities were memory-safety or resource-management errors. 27.2% were cryptographic. Only 3.6% to 11.1% of the severe ones were cryptographic. The largest class is one Rust prevents when `unsafe` is absent, so `#![forbid(unsafe_code)]` is a rule here, not a preference. The study excluded memory-safe languages, so its proportions do not transfer to Rust crates directly.
- **Kern 2024**, *Developer ecosystems for software safety* (ACM Queue 22(1) / CACM 67(6)). At Google, making the ecosystem rather than the developer responsible for safety invariants, through vocabulary types and pre-submit conformance checks, took XSS and SQL injection close to zero. Developer education alone did not reduce defect rates.

## Per rule

| Rule | Evidence |
|---|---|
| 1. Secure by default | Fischer et al. 2021 (CCS): re-ranking search results by security raised secure and functional outcomes with no behaviour change. Green & Smith 2016: defaults safe and never ambiguous. |
| 2. Tasks, not primitives | Nadi et al. 2016 (ICSE): Java developers found crypto APIs too low-level and asked for task-based ones. Bernstein et al. 2012: NaCl's `crypto_box` offers no algorithm choices. |
| 3. Own the periphery | Acar et al. 2017 (IEEE S&P): calls into the library were mostly secure; failures came from key storage, password-based derivation, and insecure inputs copied from examples. Egele et al. 2013 (CCS): 88% of 11,748 Android apps misused crypto, through mistakes such as ECB mode, constant keys and constant IVs. |
| 4. Secrets as types | Blessing et al. 2021: 11.3% of vulnerabilities in eight crypto libraries were exposure of sensitive information, the class a secret type addresses. (Indirect: the study does not test secret types.) Memory-safety errors, the largest class at 37.2%, are a separate problem that `#![forbid(unsafe_code)]` addresses; see above. |
| 5. Invalid states unrepresentable | Russell's hard-to-misuse scale: "won't compile" outranks every runtime and documentation measure. Kern 2024 (CACM / ACM Queue): at Google, changing injection-sink APIs to require vocabulary types took XSS from tens per year per application to low single digits across all framework applications, and SQL injection to a nonissue; the residual is a tracked list of legacy exemptions. Georgiev et al. 2012 (CCS): certificate validation broke where libraries exposed confusing options. |
| 6. Promise only what you deliver | Oliveira et al. 2018 (SOUPS) and Brun et al. 2023 (TOSEM): APIs with misleading names or hidden preconditions caused vulnerabilities regardless of experience. Albertini et al. 2022 (USENIX Security): callers assumed AEAD key commitment that the primitive did not give. |
| 7. Errors reveal nothing | Padding-oracle and partitioning-oracle attacks (Len, Grubbs & Ristenpart 2021) turn distinguishable failures into plaintext recovery. |
| 8. Warn at point of use | Gorski et al. 2018 (SOUPS): API warnings nearly doubled secure outcomes; code that triggered a warning was 15 times more likely to be fixed. Gorski et al. 2020 (CHI): the five parts of a warning. Vance et al. 2018 (CHI): repeated identical warnings stop being processed. Kern 2024: exemptions survive as a counted allowlist, not as individual review judgements. |
| 9. Secure, complete examples | Acar et al. 2017: code copied from Stack Overflow was about three times more likely to be functional on the symmetric tasks, and insecure inputs in examples were copied with it. Fischer et al. 2017 (IEEE S&P): insecure Stack Overflow snippets propagated into Play Store apps. |
| 10. Keep it small | Blessing et al. 2021: about one CVE per thousand lines added to OpenSSL, with ρ = 0.8 between lines added and CVEs introduced; LibreSSL and BoringSSL removed 22% and 70% of the code and with it 25% and 40.6% of the vulnerabilities. Both forks then grew back to OpenSSL's size at Heartbleed, so minimalism needs a review step, not a founding intention. |
| 11. Evolve loudly | Holmwood 2022 (linux.conf.au): Keyczar's replacement by Tink as the model of a breaking change with a migration path. Kern 2024: the rollout is deprecate, migrate, then enforce; the old path ends as a denied lint with a counted exemption list. |

Experience does not protect against footguns: Acar et al. 2017 found Python, security and library experience did not predict success, and Brun et al. 2023 found long-time professionals made as many mistakes as novices.
