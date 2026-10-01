const native = require('./stack-profile-node.js')

const CODE_RE = /^([A-Z_]+): /

function enrichError(err) {
  if (err instanceof Error) {
    const match = CODE_RE.exec(err.message)
    if (match) {
      err.code = match[1]
      err.message = err.message.slice(match[0].length)
    }
  }
  throw err
}

function wrapSync(fn) {
  return function (...args) {
    try {
      return fn.apply(this, args)
    } catch (err) {
      enrichError(err)
    }
  }
}

// Wrap ProfileStore methods that can throw
const proto = native.ProfileStore.prototype
proto.setCurrentWorkspace = wrapSync(proto.setCurrentWorkspace)
proto.currentWorkspace = wrapSync(proto.currentWorkspace)
proto.clearCurrentWorkspace = wrapSync(proto.clearCurrentWorkspace)
proto.listWorkspaces = wrapSync(proto.listWorkspaces)
proto.workspaceStore = wrapSync(proto.workspaceStore)
proto.currentWorkspaceStore = wrapSync(proto.currentWorkspaceStore)

// Wrap factory methods
const origResolve = native.ProfileStore.resolve
native.ProfileStore.resolve = wrapSync(origResolve)

module.exports = native
