# IP-Bulba-Checker: local CI parity verification script

Write-Host "`n>>> [1/4] Checking formatting (cargo fmt --check)..." -ForegroundColor Cyan
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { Write-Host "Error: cargo fmt failed." -ForegroundColor Red; exit 1 }

Write-Host "`n>>> [2/4] Checking compilation (cargo check --all-targets --all-features)..." -ForegroundColor Cyan
cargo check --verbose --all-targets --all-features
if ($LASTEXITCODE -ne 0) { Write-Host "Error: cargo check failed." -ForegroundColor Red; exit 1 }

Write-Host "`n>>> [3/4] Running linter (cargo clippy --all-targets --all-features)..." -ForegroundColor Cyan
cargo clippy --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { Write-Host "Error: cargo clippy failed." -ForegroundColor Red; exit 1 }

Write-Host "`n>>> [4/4] Running tests (cargo test --workspace --all-features --locked)..." -ForegroundColor Cyan
cargo test --verbose --workspace --all-features --locked
if ($LASTEXITCODE -ne 0) { Write-Host "Error: cargo test failed." -ForegroundColor Red; exit 1 }

Write-Host "`nAll checks passed. Local state matches CI expectations." -ForegroundColor Green
