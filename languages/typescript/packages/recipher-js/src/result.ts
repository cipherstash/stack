/**
 * A `Result`: the value of a call that worked, or the error of a call that
 * failed. A `Result` has the methods of Rust's `Result`, named in camelCase.
 * Each method does what the Rust method does.
 *
 * Only `unwrap()` and `expect(..)` throw. In Rust, they are also the only
 * `Result` methods that panic. Use them in a script, a test, or code that
 * runs at startup. Everywhere else, narrow the type with `isOk()` or
 * `isErr()`, or combine results with `map`, `andThen`, and `unwrapOr`.
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
  /** Whether this is an `Ok`. Narrows the type, as a `match` does in Rust. */
  isOk(): this is Ok<T, E>
  /** Whether this is an `Err`. Narrows the type, as a `match` does in Rust. */
  isErr(): this is Err<T, E>
  /** Returns the value, or `undefined` for an `Err`. */
  ok(): T | undefined
  /** Returns the error, or `undefined` for an `Ok`. */
  err(): E | undefined
  /**
   * For an `Ok`, returns an `Ok` of `f` applied to the value. Returns an
   * `Err` unchanged.
   */
  map<U>(f: (value: T) => U): Result<U, E>
  /**
   * For an `Err`, returns an `Err` of `f` applied to the error. Returns an
   * `Ok` unchanged.
   */
  mapErr<F>(f: (error: E) => F): Result<T, F>
  /** Returns `f` applied to the value, or `fallback` for an `Err`. */
  mapOr<U>(fallback: U, f: (value: T) => U): U
  /** For an `Ok`, returns `other`. Returns this `Err` unchanged. */
  and<U>(other: Result<U, E>): Result<U, E>
  /** For an `Ok`, returns `f` applied to the value. Returns this `Err` unchanged. */
  andThen<U>(f: (value: T) => Result<U, E>): Result<U, E>
  /** Returns this `Ok` unchanged. For an `Err`, returns `other`. */
  or<F>(other: Result<T, F>): Result<T, F>
  /** Returns this `Ok` unchanged. For an `Err`, returns `f` applied to the error. */
  orElse<F>(f: (error: E) => Result<T, F>): Result<T, F>
  /** Returns the value, or `fallback` for an `Err`. */
  unwrapOr<U = T>(fallback: U): T | U
  /** Returns the value, or `f` applied to the error for an `Err`. */
  unwrapOrElse<U = T>(f: (error: E) => U): T | U
  /**
   * Returns the value. For an `Err`, throws an `Error` whose `cause` is the
   * error.
   */
  unwrap(): T
  /**
   * Returns the value. For an `Err`, throws an `Error` whose message starts
   * with `message`, and whose `cause` is the error.
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

/** The result of a call that failed. */
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

/** Make an `Ok` that contains `value`. */
export function ok<T, E = never>(value: T): Result<T, E> {
  return new Ok(value)
}

/** Make an `Err` that contains `error`. */
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
