#!/usr/bin/env python3
# coding: utf-8
"""
Upload Qt debug symbols and matching binaries for later minidump analysis.

macOS:
  Uploads .dSYM bundles and matching Mach-O binaries, indexed by DWARF UUID.
Windows:
  Uploads PDB files and matching PE binaries, indexed by CodeView RSDS GUID+Age.

The default server is a dufs endpoint. Files are uploaded with HTTP PUT.
"""

import argparse
import json
import os
import platform
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urljoin

try:
    import requests
except ImportError as exc:
    raise SystemExit("Missing dependency: requests. Install it with: python -m pip install requests") from exc

DEFAULT_SERVER_URL = "http://internalserver.viewdepth.cn:3001/PixPinRelease/QtSymbols"

MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}
PE_EXTENSIONS = {".exe", ".dll"}
PDB_EXTENSIONS = {".pdb"}
SKIP_DIR_NAMES = {
    ".git", ".svn", ".hg", ".DS_Store", "__pycache__",
}


def should_skip_dir(path):
    path = Path(path)
    return path.name in SKIP_DIR_NAMES or path.name.endswith(".dSYM")


def log(message):
    print(message, flush=True)


def ensure_url_base(url):
    return url if url.endswith("/") else url + "/"


def quote_path(path):
    return "/".join(quote(part) for part in path.split("/"))


def put_file(local_path, remote_url, dry_run=False):
    local_path = Path(local_path)
    if dry_run:
        log(f"[dry-run] {local_path} -> {remote_url}")
        return True

    with local_path.open("rb") as file_obj:
        response = requests.put(remote_url, data=file_obj, timeout=300)

    if response.status_code in (200, 201, 204):
        log(f"Uploaded: {local_path.name}")
        return True

    log(f"Upload failed: {local_path} -> {remote_url}, status={response.status_code}, response={response.text}")
    return False


def run_text_command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(args)}\n{result.stderr}")
    return result.stdout


def walk_files(root):
    root = Path(root)
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if not should_skip_dir(Path(current_root) / name)]
        for file_name in files:
            yield Path(current_root) / file_name


def is_probable_macho(path):
    try:
        with Path(path).open("rb") as file_obj:
            return file_obj.read(4) in MACHO_MAGIC
    except OSError:
        return False


def is_probable_pe(path):
    try:
        with Path(path).open("rb") as file_obj:
            return file_obj.read(2) == b"MZ"
    except OSError:
        return False


def parse_dwarfdump_uuids(path):
    output = run_text_command(["dwarfdump", "--uuid", str(path)])
    pattern = re.compile(r"UUID:\s+([A-Fa-f0-9\-]+)\s+\(([^)]+)\)")
    uuids = []
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            uuids.append({"uuid": match.group(1).upper(), "arch": match.group(2)})
    return uuids


def dsym_binary_name(dsym_path):
    dwarf_dir = Path(dsym_path) / "Contents" / "Resources" / "DWARF"
    if not dwarf_dir.exists():
        return Path(dsym_path).stem
    for entry in dwarf_dir.iterdir():
        if entry.is_file() and entry.name != ".DS_Store":
            return entry.name
    return Path(dsym_path).stem


def find_macos_binary(build_dir, binary_name):
    build_dir = Path(build_dir)

    direct = build_dir / binary_name
    if direct.is_file():
        return direct

    app_binary = build_dir / f"{binary_name}.app" / "Contents" / "MacOS" / binary_name
    if app_binary.is_file():
        return app_binary

    framework_candidates = [
        build_dir / f"{binary_name}.framework" / "Versions" / "5" / binary_name,
        build_dir / f"{binary_name}.framework" / "Versions" / "5" / f"{binary_name}_debug",
        build_dir / f"{binary_name}.framework" / binary_name,
        build_dir / f"{binary_name}.framework" / f"{binary_name}_debug",
    ]
    for framework_binary in framework_candidates:
        if framework_binary.is_file() and is_probable_macho(framework_binary):
            return framework_binary

    for candidate in walk_files(build_dir):
        if candidate.name == binary_name and candidate.is_file() and is_probable_macho(candidate):
            return candidate

    return None


def add_directory_upload_tasks(base_url, local_dir, remote_dir, tasks):
    local_dir = Path(local_dir)
    for local_file in walk_files(local_dir):
        if local_file.name == ".DS_Store":
            continue
        rel = local_file.relative_to(local_dir).as_posix()
        remote_path = f"{remote_dir}/{rel}"
        tasks.append((local_file, urljoin(base_url, quote_path(remote_path))))


def upload_macos_symbols(build_dir, server_url, version, dry_run=False):
    build_dir = Path(build_dir)
    base_url = ensure_url_base(server_url)
    dsym_paths = sorted(build_dir.rglob("*.dSYM"))
    tasks = []
    records = []

    log(f"Found {len(dsym_paths)} dSYM bundles under {build_dir}")

    for dsym_path in dsym_paths:
        binary_name = dsym_binary_name(dsym_path)
        dsym_uuids = parse_dwarfdump_uuids(dsym_path)
        binary_path = find_macos_binary(build_dir, binary_name)
        binary_uuid_map = {}

        if binary_path:
            try:
                binary_uuid_map = {item["arch"]: item["uuid"] for item in parse_dwarfdump_uuids(binary_path)}
            except Exception as exc:
                log(f"Warning: failed to read binary UUIDs: {binary_path}: {exc}")
        else:
            log(f"Warning: binary not found for {dsym_path}")

        for item in dsym_uuids:
            arch = item["arch"]
            uuid = item["uuid"]
            dsym_remote_dir = f"macos/{binary_name}/{uuid}/{dsym_path.name}"
            binary_remote_path = None

            add_directory_upload_tasks(base_url, dsym_path, dsym_remote_dir, tasks)

            if binary_path and binary_uuid_map.get(arch) == uuid:
                binary_remote_path = f"macos/{binary_name}/{uuid}/{binary_name}"
                tasks.append((binary_path, urljoin(base_url, quote_path(binary_remote_path))))
            elif binary_path:
                log(f"Warning: UUID mismatch for {binary_name} [{arch}], dSYM={uuid}, binary={binary_uuid_map.get(arch)}")

            records.append({
                "platform": "macos",
                "binaryName": binary_name,
                "arch": arch,
                "uuid": uuid,
                "dsymRemotePath": dsym_remote_dir,
                "binaryRemotePath": binary_remote_path,
                "localDsymPath": str(dsym_path),
                "localBinaryPath": str(binary_path) if binary_path else None,
            })

    return upload_tasks_and_manifest(tasks, records, build_dir, base_url, "macos", version, dry_run)


def read_c_string(data, offset):
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def parse_pe_sections(data, pe_offset):
    file_header_offset = pe_offset + 4
    machine, section_count, _, _, _, optional_header_size, _ = struct.unpack_from("<HHIIIHH", data, file_header_offset)
    optional_offset = file_header_offset + 20
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10B:
        data_directory_offset = optional_offset + 96
    elif magic == 0x20B:
        data_directory_offset = optional_offset + 112
    else:
        raise ValueError(f"Unsupported PE optional header magic: {magic:#x}")

    debug_rva, debug_size = struct.unpack_from("<II", data, data_directory_offset + 6 * 8)
    section_offset = optional_offset + optional_header_size
    sections = []
    for index in range(section_count):
        off = section_offset + index * 40
        name = data[off:off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({
            "name": name,
            "virtualAddress": virtual_address,
            "virtualSize": virtual_size,
            "rawSize": raw_size,
            "rawPtr": raw_ptr,
        })
    return debug_rva, debug_size, sections


def rva_to_file_offset(rva, sections):
    for section in sections:
        start = section["virtualAddress"]
        size = max(section["virtualSize"], section["rawSize"])
        if start <= rva < start + size:
            return section["rawPtr"] + (rva - start)
    return None


def parse_pe_rsds(path):
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return None

    debug_rva, debug_size, sections = parse_pe_sections(data, pe_offset)
    if not debug_rva or not debug_size:
        return None

    debug_offset = rva_to_file_offset(debug_rva, sections)
    if debug_offset is None:
        return None

    entry_count = debug_size // 28
    for index in range(entry_count):
        entry_offset = debug_offset + index * 28
        if entry_offset + 28 > len(data):
            break
        _, _, _, _, debug_type, size_of_data, address_of_raw_data, pointer_to_raw_data = struct.unpack_from("<IIHHIIII", data, entry_offset)
        if debug_type != 2 or pointer_to_raw_data <= 0 or size_of_data < 24:
            continue
        if pointer_to_raw_data + size_of_data > len(data):
            pointer_to_raw_data = rva_to_file_offset(address_of_raw_data, sections)
            if pointer_to_raw_data is None or pointer_to_raw_data + size_of_data > len(data):
                continue
        if data[pointer_to_raw_data:pointer_to_raw_data + 4] != b"RSDS":
            continue
        guid_bytes = data[pointer_to_raw_data + 4:pointer_to_raw_data + 20]
        age = struct.unpack_from("<I", data, pointer_to_raw_data + 20)[0]
        pdb_path = read_c_string(data, pointer_to_raw_data + 24)
        d1, d2, d3 = struct.unpack_from("<IHH", guid_bytes, 0)
        d4 = guid_bytes[8:]
        guid = f"{d1:08X}{d2:04X}{d3:04X}" + "".join(f"{byte:02X}" for byte in d4)
        identifier = f"{guid}{age:X}"
        return {
            "guid": guid,
            "age": age,
            "identifier": identifier,
            "pdbPath": pdb_path,
            "pdbName": Path(pdb_path).name,
        }
    return None


def collect_pdbs(build_dir):
    pdbs = {}
    for path in walk_files(build_dir):
        if path.suffix.lower() in PDB_EXTENSIONS:
            pdbs.setdefault(path.name.lower(), []).append(path)
    return pdbs


def choose_pdb(pdbs, pdb_name):
    matches = pdbs.get(pdb_name.lower(), [])
    if not matches:
        return None
    return sorted(matches, key=lambda p: len(str(p)))[0]


def upload_windows_symbols(build_dir, server_url, version, dry_run=False):
    build_dir = Path(build_dir)
    base_url = ensure_url_base(server_url)
    pdbs = collect_pdbs(build_dir)
    tasks = []
    records = []

    pe_files = [path for path in walk_files(build_dir) if path.suffix.lower() in PE_EXTENSIONS and is_probable_pe(path)]
    log(f"Found {len(pe_files)} PE binaries under {build_dir}")

    for binary_path in sorted(pe_files):
        rsds = parse_pe_rsds(binary_path)
        if not rsds:
            continue

        pdb_path = choose_pdb(pdbs, rsds["pdbName"])
        identifier = rsds["identifier"]
        binary_remote_path = f"windows/{binary_path.name}/{identifier}/{binary_path.name}"
        pdb_remote_path = None

        tasks.append((binary_path, urljoin(base_url, quote_path(binary_remote_path))))
        if pdb_path:
            pdb_remote_path = f"windows/{rsds['pdbName']}/{identifier}/{rsds['pdbName']}"
            tasks.append((pdb_path, urljoin(base_url, quote_path(pdb_remote_path))))
        else:
            log(f"Warning: PDB not found for {binary_path}: {rsds['pdbName']}")

        records.append({
            "platform": "windows",
            "binaryName": binary_path.name,
            "pdbName": rsds["pdbName"],
            "identifier": identifier,
            "guid": rsds["guid"],
            "age": rsds["age"],
            "pdbRemotePath": pdb_remote_path,
            "binaryRemotePath": binary_remote_path,
            "localPdbPath": str(pdb_path) if pdb_path else None,
            "localBinaryPath": str(binary_path),
        })

    return upload_tasks_and_manifest(tasks, records, build_dir, base_url, "windows", version, dry_run)


def upload_tasks_and_manifest(tasks, records, build_dir, base_url, platform_name, version, dry_run=False):
    if not records:
        log("No debug symbol records found")
        return False

    manifest = {
        "schemaVersion": 1,
        "platform": platform_name,
        "version": version,
        "buildDir": str(build_dir),
        "records": records,
    }
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", prefix="qt_symbols_", delete=False) as file_obj:
        json.dump(manifest, file_obj, indent=2, ensure_ascii=False)
        manifest_path = Path(file_obj.name)

    manifest_name_parts = ["qt", platform_name]
    if version:
        manifest_name_parts.append(version)
    manifest_name_parts.append(Path(build_dir).name)
    manifest_remote_path = f"manifests/{'_'.join(manifest_name_parts)}.json"
    tasks.append((manifest_path, urljoin(base_url, quote_path(manifest_remote_path))))

    # Avoid uploading the same large file repeatedly when multiple architectures share a universal binary.
    unique_tasks = []
    seen = set()
    for local_path, remote_url in tasks:
        key = (str(Path(local_path).resolve()), remote_url)
        if key in seen:
            continue
        seen.add(key)
        unique_tasks.append((local_path, remote_url))

    log(f"Uploading {len(unique_tasks)} files to {base_url}")
    success_count = 0
    try:
        for local_path, remote_url in unique_tasks:
            if put_file(local_path, remote_url, dry_run=dry_run):
                success_count += 1
    finally:
        try:
            manifest_path.unlink(missing_ok=True)
        except Exception:
            pass

    log(f"Upload completed: {success_count}/{len(unique_tasks)} files succeeded")
    return success_count == len(unique_tasks)


def detect_platform(name):
    if name != "auto":
        return name
    system_name = platform.system().lower()
    if system_name == "darwin":
        return "macos"
    if system_name == "windows":
        return "windows"
    raise SystemExit(f"Unsupported platform: {system_name}. Use --platform macos or --platform windows.")


def main():
    parser = argparse.ArgumentParser(description="Upload Qt debug symbols and binaries for minidump analysis")
    parser.add_argument("--platform", choices=["auto", "macos", "windows"], default="auto", help="Target platform. Default: auto")
    parser.add_argument("--build-dir", default="buildUniversal", help="Qt build directory. Default: buildUniversal")
    parser.add_argument("--server-url", default=DEFAULT_SERVER_URL, help=f"dufs server URL. Default: {DEFAULT_SERVER_URL}")
    parser.add_argument("--version", default=None, help="Qt package/version label stored in manifest")
    parser.add_argument("--dry-run", action="store_true", help="Print upload tasks without uploading")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    build_dir = Path(args.build_dir)
    if not build_dir.is_absolute():
        build_dir = script_dir / build_dir

    platform_name = detect_platform(args.platform)
    if platform_name == "macos":
        ok = upload_macos_symbols(build_dir, args.server_url, args.version, args.dry_run)
    else:
        ok = upload_windows_symbols(build_dir, args.server_url, args.version, args.dry_run)

    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
