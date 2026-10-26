# Qualified staged-Mesa correctness probes

MIT C sources copied unchanged from the already-reviewed render-check tools.
The agent does not compile code on the Mac. It downloads these two approved ARM64
ELF artifacts from the ordinary authenticated CAS and independently rehashes them
before any execution:

- GL: `24007754c92e05220edc4645702853ac86c0ff5d98c084da126955ccdd4d6e82`
- Vulkan: `e4a7b8d50c10d1cc3bf40c1dcaf9e74cd566ebb1901857e84b06256bbdf0d40d`

An authorized operator supplies the existing qualified binaries with `lab upload`.
These small builtin tool references remain pinned by GC. A different rebuild is
not silently admitted under the old qualified hash: source/build provenance and
the new exact hash must be reviewed before updating the registry.

The only invocation is `<probe> 3`: a three-second pixel-correctness check. No
`--no-check`, renderer override or arbitrary tool arguments are accepted. A stage
passes only when both helpers report zero wrong pixels, the actual Apple renderer,
the exact staged EGL+Gallium/Vulkan implementation mappings, actual render-node
use, fresh clean kernel journal, matching system state and genuine unit cleanup.
Host compilation/parser fixtures are not GPU or board qualification.
