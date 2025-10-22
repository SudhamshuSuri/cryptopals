# cryptopals

Solutions and experimenting ground for the Cryptopals crypto challenges — implemented in Go.

> A personal implementation of selected Cryptopals challenges. Intended for learning cryptography primitives, Go crypto libraries, and low-level byte operations.

## Repository structure

.
├── challenges/ # challenge-specific code and helper packages
├── ch7.txt # notes or challenge hints
├── ch8.txt
├── ch10.txt
├── go.mod
├── main.go # runner / examples


> The repo is organized by challenge. Each challenge should live under `challenges/` with a short README or comments explaining the approach.

## Prerequisites

- Go (1.20+) installed and available in `PATH`.
- Basic familiarity with Go modules and `go run` / `go build`.
- Recommended: knowledge of byte-level operations, base64, AES, ECB/CBC, and HMAC.

## Quick start

Clone the repo:

```bash
git clone https://github.com/SudhamshuSuri/cryptopals.git
cd cryptopals
```

When in doubt, add a small main that prints intermediate values (hex/base64) to debugBuild or run the main program:
