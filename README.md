# flint-security

The security repo of [Flint](https://github.com/flint-projects/flint), a integrated repo. It was extracted from the Flint monorepo with its history (ADR-030; the ADR-023 amendment on platform modules).

Mirror of `flint-projects/flint` until the Phase 1 cutover (ADR-030); do not push here directly.

Its packages keep their `flint:*` names and resolve at this repo's platform version, which the flint repo's `platform.lock` pins. It may depend on `data-commons`, `framework`, `flint`.

## Porting

The rules are the flint repo's: [AGENTS.md](https://github.com/flint-projects/flint/blob/main/AGENTS.md) and, before porting a module and again before committing it, the [performance playbook](https://github.com/flint-projects/flint/blob/main/docs/spring/performance-playbook.md). A `docs/` path that a source file here cites is in the flint repo.

## Building

Check out the repos it depends on and describe them in a `flint.workspace/1` file, then, from the flint repo:

```bash
python3 tools/workspace.py dub-root --workspace workspace.json --output .flint/workspace
dub test flint:<package> --root=.flint/workspace
python3 tools/gates.py --gate structural --workspace workspace.json --repo security
```
