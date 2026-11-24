/**
 * A `Result`: the value of a call that worked, or the error of one that did
 * not. It has Rust's `Result` methods, in camelCase, and each does what
 * Rust's does.
 *
 * `unwrap()` and `expect(..)` are the only methods that throw, as they are
 * the only ones that panic in Rust. Use them in a script, a test or a
 * startup path. Everywhere else, narrow with `isOk()` or `isErr()`, or
 * combine with `map`, `andThen` and `unwrapOr`.
 *
 * ```ts
 * const sealed = await keyset.encrypt('a secret message')
 * if (sealed.isErr()) {
 *   return sealed
 * }
 * store(sealed.value.toBytes())
 * ```
 */
export type Result<T, E> = Ok<T, E> | Err<T, E>

interface Methods<T, E> {
  /** Whether this is an `Ok`. Narrows the type, as a Rust `match` does. */
  isOk(): this is Ok<T, E>
  /** Whether this is an `Err`. Narrows the type, as a Rust `match` does. */
  isErr(): this is Err<T, E>
  /** The value, or `undefined` for an `Err`. */
  ok(): T | undefined
  /** The error, or `undefined` for an `Ok`. */
  err(): E | undefined
  /** An `Ok` with `f` applied to its value; an `Err` as it is. */
  map<U>(f: (value: T) => U): Result<U, E>
  /** An `Err` with `f` applied to its error; an `Ok` as it is. */
  mapErr<F>(f: (error: E) => F): Result<T, F>
  /** `f` applied to the value, or `fallback` for an `Err`. */
  mapOr<U>(fallback: U, f: (value: T) => U): U
  /** `other` for an `Ok`; this `Err` as it is. */
  and<U>(other: Result<U, E>): Result<U, E>
  /** `f` applied to the value for an `Ok`; this `Err` as it is. */
  andThen<U>(f: (value: T) => Result<U, E>): Result<U, E>
  /** This `Ok` as it is; `other` for an `Err`. */
  or<F>(other: Result<T, F>): Result<T, F>
  /** This `Ok` as it is; `f` applied to the error for an `Err`. */
  orElse<F>(f: (error: E) => Result<T, F>): Result<T, F>
  /** The value, or `fallback` for an `Err`. */
  unwrapOr<U = T>(fallback: U): T | U
  /** The value, or `f` applied to the error for an `Err`. */
  unwrapOrElse<U = T>(f: (error: E) => U): T | U
  /**
   * The value. Throws for an `Err`, with the error as the thrown error's
   * `cause`.
   */
  unwrap(): T
  /**
   * The value. Throws for an `Err`, with `message` and the error as the
   * thrown error's `cause`.
   */
  expect(message: string): T
}

/** The result of a call that worked. */
export class Ok<T, E> implements Methods<T, E> {
  readonly value: T

  constructor(value: T) {
    this.value = value
    Object.freeze(this)
  }

  isOk(): this is Ok<T, E> {
    return true
  }
  isErr(): this is Err<T, E> {
    return false
  }
  ok(): T {
    return this.value
  }
  err(): undefined {
    return undefined
  }
  map<U>(f: (value: T) => U): Result<U, E> {
    return new Ok(f(this.value))
  }
  mapErr<F>(_f: (error: E) => F): Result<T, F> {
    return new Ok(this.value)
  }
  mapOr<U>(_fallback: U, f: (value: T) => U): U {
    return f(this.value)
  }
  and<U>(other: Result<U, E>): Result<U, E> {
    return other
  }
  andThen<U>(f: (value: T) => Result<U, E>): Result<U, E> {
    return f(this.value)
  }
  or<F>(_other: Result<T, F>): Result<T, F> {
    return new Ok(this.value)
  }
  orElse<F>(_f: (error: E) => Result<T, F>): Result<T, F> {
    return new Ok(this.value)
  }
  unwrapOr<U = T>(_fallback: U): T | U {
    return this.value
  }
  unwrapOrElse<U = T>(_f: (error: E) => U): T | U {
    return this.value
  }
  unwrap(): T {
    return this.value
  }
  expect(_message: string): T {
    return this.value
  }
}

/** The result of a call that did not work. */
export class Err<T, E> implements Methods<T, E> {
  readonly error: E

  constructor(error: E) {
    this.error = error
    Object.freeze(this)
  }

  isOk(): this is Ok<T, E> {
    return false
  }
  isErr(): this is Err<T, E> {
    return true
  }
  ok(): undefined {
    return undefined
  }
  err(): E {
    return this.error
  }
  map<U>(_f: (value: T) => U): Result<U, E> {
    return new Err(this.error)
  }
  mapErr<F>(f: (error: E) => F): Result<T, F> {
    return new Err(f(this.error))
  }
  mapOr<U>(fallback: U, _f: (value: T) => U): U {
    return fallback
  }
  and<U>(_other: Result<U, E>): Result<U, E> {
    return new Err(this.error)
  }
  andThen<U>(_f: (value: T) => Result<U, E>): Result<U, E> {
    return new Err(this.error)
  }
  or<F>(other: Result<T, F>): Result<T, F> {
    return other
  }
  orElse<F>(f: (error: E) => Result<T, F>): Result<T, F> {
    return f(this.error)
  }
  unwrapOr<U = T>(fallback: U): T | U {
    return fallback
  }
  unwrapOrElse<U = T>(f: (error: E) => U): T | U {
    return f(this.error)
  }
  unwrap(): never {
    throw new Error(`called unwrap() on an Err: ${describe(this.error)}`, {
      cause: this.error,
    })
  }
  expect(message: string): never {
    throw new Error(`${message}: ${describe(this.error)}`, {
      cause: this.error,
    })
  }
}

/** An `Ok` holding `value`. */
export function ok<T, E = never>(value: T): Result<T, E> {
  return new Ok(value)
}

/** An `Err` holding `error`. */
export function err<E, T = never>(error: E): Result<T, E> {
  return new Err(error)
}

function describe(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  if (typeof error === 'object' && error !== null && 'message' in error) {
    return String(error.message)
  }
  return String(error)
}
