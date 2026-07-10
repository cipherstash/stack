import { runFamilySuite } from '@cipherstash/test-kit/suite'
import { makeSupabaseAdapter } from './adapter'

runFamilySuite('boolean', makeSupabaseAdapter)
