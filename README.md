# Hachimi Standalone iOS Tweaks

This repository contains the decoupled standalone iOS tweaks for **Uma-Proxy** and **Packet-Capture** plugins.

## Features
- **Standalone injection support:** The plugins are compiled directly as iOS dynamic libraries (`.dylib`) and hook the game processes using the Dobby framework.
- **Clean initialization:** Bypasses startup crashes by hooking `il2cpp_init` safely, avoiding spawning background threads during global constructor execution.
- **Self-contained:** The Dobby hooking framework is statically compiled and merged into the plugins, removing any runtime dependencies on external dylibs.
- **GitHub Actions support:** Comes with pre-configured workflows to cross-compile the tweaks for physical iOS devices (`arm64`).

## Directory Structure
- `.github/workflows/build_ios.yml`: GitHub Actions workflow to build the tweaks.
- `plugins/Uma-Proxy/`: Standalone proxy server interception tweak.
- `plugins/Packet-Capture/`: Standalone HTTP request/response capturing tweak.
- `tools/trigger_workflow.py`: Python script to trigger the build workflow.

## How to Build

### 1. Build via GitHub Actions
Run the workflow manually via GitHub UI, or execute the triggering script:
```bash
python tools/trigger_workflow.py
```

### 2. Build locally (macOS/iOS SDK)
Ensure you have Xcode installed and run:
```bash
# Example for Uma-Proxy
cmake -B plugins/Uma-Proxy/build -S plugins/Uma-Proxy \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_SYSTEM_PROCESSOR=arm64 \
  -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DDOBBY_GENERATE_SHARED=OFF
cmake --build plugins/Uma-Proxy/build --config Release
```
