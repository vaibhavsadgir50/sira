# Installing from the Git repository

You can depend on this repo **without** publishing to PyPI or npm first.

## pip (Python)

Install the **`sira-python`** package from the `sira-python/` subdirectory:

```bash
pip install "git+https://github.com/vaibhavsadgir50/sira.git#subdirectory=sira-python"
```

Pin a branch or tag:

```bash
pip install "git+https://github.com/vaibhavsadgir50/sira.git@main#subdirectory=sira-python"
```

Optional dev tools (pytest, etc.):

```bash
pip install "git+https://github.com/vaibhavsadgir50/sira.git#subdirectory=sira-python[dev]"
```

In **`requirements.txt`**:

```text
sira-python @ git+https://github.com/vaibhavsadgir50/sira.git@main#subdirectory=sira-python
```

The importable package name is **`sira`** (e.g. `from sira import SiraServer`).

---

## npm (Node.js)

**npm** clones the repo and expects **`package.json` at the repository root**, so there is no official one-URL install for `sira-node` or `sira-js` inside this monorepo (unlike pip’s `#subdirectory=`).

Use one of these:

### 1. `file:` after clone (simplest)

```bash
git clone https://github.com/vaibhavsadgir50/sira.git
cd your-app
npm install ../sira/sira-node
# or
npm install ../sira/sira-js
```

### 2. Git submodule

Add the repo as a submodule, then:

```bash
npm install file:./vendor/sira/sira-node
```

### 3. Package managers with git subpaths

Some tools support a path into a git URL (for example **pnpm**). Check your package manager’s docs for `git` + subdirectory.

### 4. Publish to npm

For one-line `npm install sira-node` for consumers, publish `sira-node` and `sira-js` to the npm registry (scoped packages like `@your-scope/sira-node` are fine).

---

## Rust

The reference server/library is the **workspace root** (`Cargo.toml` at repo root). Clone and use a path dependency:

```toml
[dependencies]
sira = { git = "https://github.com/vaibhavsadgir50/sira" }
```

Or depend on **`sira-cli`** from the `sira-cli/` directory using `[workspace]` / path, or a future crates.io publish.
