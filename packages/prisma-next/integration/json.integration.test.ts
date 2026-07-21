import { runJsonSuite } from '@cipherstash/test-kit/json-suite'
import { makePrismaNextJsonAdapter } from './json-adapter'

runJsonSuite(makePrismaNextJsonAdapter)
