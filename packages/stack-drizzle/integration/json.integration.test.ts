import { runJsonSuite } from '@cipherstash/test-kit/json-suite'
import { makeDrizzleJsonAdapter } from './json-adapter'

runJsonSuite(makeDrizzleJsonAdapter)
