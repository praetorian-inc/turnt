#!/bin/bash
set -e

command -v go >/dev/null 2>&1 || { echo >&2 "❌ go is not installed. Aborting."; exit 1; }
command -v upx >/dev/null 2>&1 || { echo >&2 "❌ upx is not installed. Aborting."; exit 1; }
command -v zip >/dev/null 2>&1 || { echo >&2 "❌ zip is not installed. Aborting."; exit 1; }

PLATFORMS=(
  "linux amd64"
  "linux arm64"
  "linux 386"
  "windows amd64"
  "windows arm64"
  "windows 386"
  "darwin amd64"
  "darwin arm64"
)

OUTPUT_DIR="bin"
mkdir -p "$OUTPUT_DIR"

BINARIES=(
  "turnt-relay ./cmd/relay/relay.go yes"
  "turnt ./cmd/turnt/ no"
)

# Clean up old zip files
rm -f "$OUTPUT_DIR/turnt-windows.zip"
rm -f "$OUTPUT_DIR/turnt-linux.zip"
rm -f "$OUTPUT_DIR/turnt-macos.zip"

for binary in "${BINARIES[@]}"; do
  read -r NAME SRC STRIP <<< "$binary"
  for platform in "${PLATFORMS[@]}"; do
    read -r GOOS GOARCH <<< "$platform"
    
    # Skip unsupported darwin/386
    if [[ "$GOOS" == "darwin" && "$GOARCH" == "386" ]]; then
      echo "⚠️  Skipping unsupported target darwin/386"
      continue
    fi
    
    # Skip non-relay binaries on Windows (operator tools are Linux/macOS only)
    if [[ "$GOOS" == "windows" && "$NAME" != "turnt-relay" ]]; then
      echo "⚠️  Skipping $NAME for Windows platform"
      continue
    fi
    
    EXT=""
    [ "$GOOS" == "windows" ] && EXT=".exe"
    OUTFILE_BASE="${OUTPUT_DIR}/${NAME}-${GOOS}-${GOARCH}${EXT}"
    
    if [[ "$STRIP" == "yes" ]]; then
      echo "🔨 Building stripped $OUTFILE_BASE..."
      GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "$OUTFILE_BASE" "$SRC"
      
      # For turnt-relay on Windows (except ARM64), build both UPX and non-UPX versions
      if [[ "$NAME" == "turnt-relay" && "$GOOS" == "windows" && "$GOARCH" != "arm64" ]]; then
        # Add non-UPX version to zip
        case "$GOOS" in
          "windows") zip -j "$OUTPUT_DIR/turnt-windows.zip" "$OUTFILE_BASE" ;;
          "linux") zip -j "$OUTPUT_DIR/turnt-linux.zip" "$OUTFILE_BASE" ;;
          "darwin") zip -j "$OUTPUT_DIR/turnt-macos.zip" "$OUTFILE_BASE" ;;
        esac
        
        # Create and add UPX version
        OUTFILE_UPX="${OUTPUT_DIR}/${NAME}-${GOOS}-${GOARCH}-upx${EXT}"
        cp "$OUTFILE_BASE" "$OUTFILE_UPX"
        echo "📦 Compressing $OUTFILE_UPX with UPX..."
        upx --best --lzma "$OUTFILE_UPX"
        case "$GOOS" in
          "windows") zip -j "$OUTPUT_DIR/turnt-windows.zip" "$OUTFILE_UPX" ;;
          "linux") zip -j "$OUTPUT_DIR/turnt-linux.zip" "$OUTFILE_UPX" ;;
          "darwin") zip -j "$OUTPUT_DIR/turnt-macos.zip" "$OUTFILE_UPX" ;;
        esac
      else
        echo "⏩ Skipping UPX for $GOOS/$GOARCH"
        # Add regular version to zip
        case "$GOOS" in
          "windows") zip -j "$OUTPUT_DIR/turnt-windows.zip" "$OUTFILE_BASE" ;;
          "linux") zip -j "$OUTPUT_DIR/turnt-linux.zip" "$OUTFILE_BASE" ;;
          "darwin") zip -j "$OUTPUT_DIR/turnt-macos.zip" "$OUTFILE_BASE" ;;
        esac
      fi
    else
      echo "🔧 Building (no strip) $OUTFILE_BASE..."
      GOOS=$GOOS GOARCH=$GOARCH go build -o "$OUTFILE_BASE" "$SRC"
      # Add to zip
      case "$GOOS" in
        "windows") zip -j "$OUTPUT_DIR/turnt-windows.zip" "$OUTFILE_BASE" ;;
        "linux") zip -j "$OUTPUT_DIR/turnt-linux.zip" "$OUTFILE_BASE" ;;
        "darwin") zip -j "$OUTPUT_DIR/turnt-macos.zip" "$OUTFILE_BASE" ;;
      esac
    fi
  done
done

echo -e "\n✅ All builds complete. Binaries are in $OUTPUT_DIR/"
echo -e "📦 Platform-specific zip files created:"
echo "   - $OUTPUT_DIR/turnt-windows.zip"
echo "   - $OUTPUT_DIR/turnt-linux.zip"
echo "   - $OUTPUT_DIR/turnt-macos.zip"
