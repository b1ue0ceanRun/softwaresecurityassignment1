# Initial Lifecycle Plan

## 1. Requirements

Choose a small private-notes application with three separate HTTP processes: API,
Resource and Processor. Define Alice and Bob as normal users and Admin as a
privileged user. Record the protected asset, owner, allowed actions, trust
boundaries and basic threats. The main security requirement is that a user can
only access their own notes.

## 2. Implementation and build

Implement login, note creation, note reading, note export and administrator
statistics. Use a separately installed helper package for text export. Use short-
lived sessions and capabilities containing the user, action, resource ID,
audience and expiration time. Keep the vulnerable fixtures separate from the
normal fixed path. Check that only the approved local helper is installed.

## 3. Testing

Start a fresh three-process environment and test normal functions, cross-user
access, administrator authorization, expired authority and malformed input. Add
four small PoCs for CWE-20, CWE-89, CWE-862 and the cross-service confused deputy.
For each PoC, confirm that the vulnerable fixture returns a flag and that the
fixed version rejects the same request. Run static analysis and dependency
analysis. Any failed security or authorization test blocks release.

## 4. Release and operation

Use Jenkins to install dependencies, compile the source, run static and dependency
checks, execute the tests and archive the results on pushes and pull requests.
For a real deployment, add TLS, managed secrets, separate process identities,
persistent storage, backups, rate limiting and audit logging. The assignment
version remains a local demonstration and does not include public hosting.
