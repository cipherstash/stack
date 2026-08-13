# Postgres data security with CipherStash

This page gives a high-level overview of CipherStash's encryption in use solution, including CipherStash Proxy and the Encrypt Query Language (EQL). It's designed for developers and engineers who need to implement robust data security in PostgreSQL without sacrificing performance or usability.

## On this page

1. [Encryption in use](#encryption-in-use)
   - [What is encryption in use?](#what-is-encryption-in-use)
   - [Why use encryption in use?](#why-use-encryption-in-use)
2. [CipherStash Proxy](#cipherstash-proxy)
   - [How it works](#how-it-works)
3. [CipherStash Stack](#cipherstash-stack)
   - [How it works](#how-it-works-1)
4. [Encrypt Query Language (EQL)](#encrypt-query-language-eql)
5. [Best practices](#best-practices)
6. [Getting started](#getting-started)

## Encryption in use

CipherStash's encryption in use solution, comprising CipherStash Proxy and EQL, provides a practical way to enhance data security in Postgres databases. 
EQL enables encryption in use without significant changes to your application code.
A variety of searchable encryption techniques are available, including:

- **Matching** - Equality or partial matches
- **Ordering** - comparison operations using order-preserving encryption (CLLW-OPE by default; block-ORE as an opt-in variant)
- **Uniqueness** - enforcing unique constraints
- **Containment** - containment queries using structured encryption

### What is encryption in use?

Encryption in use is the practice of keeping data encrypted even while it's being processed or queried in the database. 
Unlike traditional encryption methods that secure data only at rest (on disk) or in transit (over the network), encryption in use keeps the data encrypted while operations are being performed on the data.
This provides an additional layer of security against unauthorized access — an adversary needs access to the encrypted data _and_ encryption keys. 

### Why use encryption in use?

While encryption at rest and in transit are essential, they don't protect data when the database server itself is compromised. 
Encryption in use mitigates this risk by ensuring that:

- **Data remains secure**: Even if the database server is breached, the data remains encrypted and unreadable without the proper keys.
- **Compliance controls are stronger**: When you need stronger data security controls than what SOC2/SOC3 or ISO27001 mandate, encryption in use helps you meet those stringent requirements.

## CipherStash Proxy

CipherStash Proxy is a transparent proxy that sits between your application and your PostgreSQL database.
It intercepts SQL queries and handles the encryption and decryption of data on-the-fly.
This enables encryption in use without significant changes to your application code.

### How it works

- **Intercepts queries**: CipherStash Proxy captures SQL statements from the client application.
- **Encrypts data**: For write operations, it encrypts the plaintext data before sending it to the database.
- **Decrypts data**: For read operations, it decrypts the encrypted data retrieved from the database before returning it to the client.
- **Maintains searchability**: Ensures that the encrypted data is searchable and retrievable without sacrificing performance or application functionality.

## CipherStash Stack

CipherStash Stack ([`@cipherstash/stack`](https://github.com/cipherstash/stack)) is an npm package that provides a set of functions to encrypt and decrypt data.
It is a client-side library that can be used to encrypt and decrypt data in your JS/TS application.

### How it works

- **Encrypts data**: CipherStash Stack encrypts the plaintext data before sending it to the database.
- **Decrypts data**: CipherStash Stack decrypts the encrypted data retrieved from the database before returning it to the client.
- **Maintains searchability**: Ensures that the encrypted data is searchable and retrievable without sacrificing performance or application functionality.

## Encrypt Query Language (EQL)

Encrypt Query Language (EQL) is a set of PostgreSQL functions and data types provided by CipherStash to work with encrypted data and indexes.
EQL allows you to perform queries on encrypted data without decrypting it, supporting operations like equality checks, range queries, and unique constraints.

## Best practices

- **Use EQL functions** when interacting with encrypted data.
- **Define database constraints** to maintain data integrity.
- **Secure key management** of encryption keys.
- **Monitor query performance** and optimize as needed.

## Getting started

Use one of the CipherStash integrations using EQL to get started.

- [CipherStash Stack](https://github.com/cipherstash/stack)
- [CipherStash Proxy](https://github.com/cipherstash/proxy)
- [Protect.php](https://github.com/cipherstash/protectphp)

For further help, raise an issue [here](https://github.com/cipherstash/encrypt-query-language/issues).

---

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/encrypt-query-language/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20WHY.md)
