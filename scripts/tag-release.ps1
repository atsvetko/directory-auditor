# Tag a release and let .github/workflows/release.yml build and publish it (PowerShell 7).
# Usage: scripts\tag-release.ps1 v0.1.0-rc1 [commit]   (default: origin/main)
param([Parameter(Mandatory)][string]$Tag, [string]$Commit = "origin/main")
$ErrorActionPreference = "Stop"; $PSNativeCommandUseErrorActionPreference = $true
if ($Tag -notmatch '^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { throw "refusing: $Tag is not vX.Y.Z[-suffix]" }
git fetch -q origin
$sha = (git rev-parse $Commit).Trim()
$existing = git tag -l $Tag
if ($existing) {
  $have = (git rev-parse "$Tag^{commit}").Trim()
  if ($have -ne $sha) { throw "refusing: $Tag already points at $have, not $sha" }
  Write-Host "tag $Tag already exists locally at $sha"
} else {
  git tag -a $Tag $sha -m "Directory Auditor $Tag"
}
Write-Host "pushing $Tag ($sha) — the release workflow builds and publishes it"
git push origin "refs/tags/$Tag"
Write-Host "watch: https://github.com/atsvetko/directory-auditor/actions/workflows/release.yml"
