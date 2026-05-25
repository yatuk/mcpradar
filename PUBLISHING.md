# Publishing MCPRadar

## One-time setup (PyPI Trusted Publisher)

1. Go to https://pypi.org/manage/project/mcpradar/settings/publishing/
2. Click "Add a new publisher"
3. Fill in:
   - **Owner:** `yatuk`
   - **Repository:** `mcpradar`
   - **Workflow:** `release.yml`
   - **Environment:** `pypi`
4. Click "Add"

Done. No PyPI token needed — GitHub Actions OIDC handles auth.

## Release a new version

```bash
# 1. Update version in pyproject.toml
# 2. Update CHANGELOG.md (add new version section)
# 3. Tag and push
git tag v0.1.0
git push origin v0.1.0
```

CI will automatically:
1. Build the wheel (`uv build`)
2. Publish to PyPI (OIDC trusted publisher)
3. Create a GitHub Release with changelog notes

## Verify

```bash
pip install mcpradar
mcpradar --version
```

## Test publish (first time only)

For the first release, publish to Test PyPI first:

```bash
uv build
uv publish --repository testpypi
```

Then install from test:

```bash
pip install -i https://test.pypi.org/simple/ mcpradar
```

If everything works, tag v0.1.0 and push.
