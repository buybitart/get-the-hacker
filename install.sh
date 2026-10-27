#!/usr/bin/env bash
# Add the gth.sh command. No packages or system services are changed.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${GTH_BIN_DIR:-}" ]]; then
  BIN_DIR="$GTH_BIN_DIR"
elif [[ "${PREFIX:-}" == *com.termux* ]]; then
  BIN_DIR="$PREFIX/bin"
else
  BIN_DIR="$HOME/.local/bin"
fi
mkdir -p -- "$BIN_DIR"
TARGET="$BIN_DIR/gth.sh"
if [[ -e "$TARGET" || -L "$TARGET" ]]; then
  printf 'Error: Command already exists: %s\n' "$TARGET" >&2
  exit 1
fi
# Bash %q quotes spaces and shell symbols in the project path.
(set -o noclobber; printf '#!/usr/bin/env bash\n# GTH launcher: Aliaksandr Zasinets\nexec bash %q "$@"\n' "$ROOT/gth.sh" > "$TARGET")
chmod u+x -- "$TARGET"
printf 'Command saved: %s\n' "$TARGET"
case ":$PATH:" in
  *":$BIN_DIR:"*) printf 'Start: gth.sh\n' ;;
  *) printf 'Add this folder to PATH: %s\nStart here: bash "%s/gth.sh"\n' "$BIN_DIR" "$ROOT" ;;
esac
