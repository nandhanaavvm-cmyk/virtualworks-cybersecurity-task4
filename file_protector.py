import base64
import hashlib
import os


def _derive_key_stream(passphrase: str, length: int) -> bytes:
    """Generate a deterministic byte stream from the passphrase using SHA-256 blocks."""
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hashlib.sha256(f"{passphrase}:{counter}".encode("utf-8")).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _xor_bytes(data: bytes, passphrase: str) -> bytes:
    key_stream = _derive_key_stream(passphrase, len(data))
    return bytes(b ^ k for b, k in zip(data, key_stream))


def protect_file(input_path: str, output_path: str, passphrase: str) -> None:
    with open(input_path, "rb") as f:
        raw_bytes = f.read()

    # Include a short verification tag so wrong passphrases are caught on restore
    verifier = hashlib.sha256(passphrase.encode("utf-8")).digest()[:4]
    payload = verifier + raw_bytes
    obfuscated = _xor_bytes(payload, passphrase)
    encoded_text = base64.b64encode(obfuscated).decode("ascii")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("PROTECTED_FILE_V1\n")
        f.write(encoded_text + "\n")


def restore_file(protected_path: str, output_path: str, passphrase: str) -> bool:
    with open(protected_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]

    if len(lines) < 2 or lines[0] != "PROTECTED_FILE_V1":
        print("Error: Invalid or unrecognized protected file format.")
        return False

    try:
        obfuscated = base64.b64decode(lines[1].encode("ascii"), validate=True)
    except Exception:
        print("Error: Protected file data is corrupted.")
        return False

    decoded = _xor_bytes(obfuscated, passphrase)
    if len(decoded) < 4:
        print("Error: Protected file is too short or corrupted.")
        return False

    expected_verifier = hashlib.sha256(passphrase.encode("utf-8")).digest()[:4]
    actual_verifier = decoded[:4]

    if actual_verifier != expected_verifier:
        print("Error: Incorrect passphrase or file has been tampered with.")
        return False

    restored_bytes = decoded[4:]
    with open(output_path, "wb") as f:
        f.write(restored_bytes)

    return True


def main():
    print("=== File Protection Utility ===")
    print("1. Protect (encode) a file")
    print("2. Restore (decode) a file")
    choice = input("Choose an option (1 or 2): ").strip()

    if choice == "1":
        source = input("Enter path of file to protect: ").strip().strip('"')
        if not os.path.isfile(source):
            print("Error: Source file not found.")
            return

        default_out = f"{source}.prot"
        dest = input(f"Enter output protected file path (press Enter for '{default_out}'): ").strip().strip('"')
        if not dest:
            dest = default_out

        passphrase = input("Enter a passphrase: ")
        if not passphrase:
            print("Error: Passphrase cannot be empty.")
            return

        protect_file(source, dest, passphrase)
        print(f"Success: Protected file saved to '{dest}'.")

    elif choice == "2":
        source = input("Enter path of protected file: ").strip().strip('"')
        if not os.path.isfile(source):
            print("Error: Protected file not found.")
            return

        default_out = "restored_" + os.path.basename(source).removesuffix(".prot")
        dest = input(f"Enter output restored file path (press Enter for '{default_out}'): ").strip().strip('"')
        if not dest:
            dest = default_out

        passphrase = input("Enter the passphrase: ")
        if not passphrase:
            print("Error: Passphrase cannot be empty.")
            return

        if restore_file(source, dest, passphrase):
            print(f"Success: Original file restored to '{dest}'.")

    else:
        print("Error: Invalid option. Please enter 1 or 2.")


if __name__ == "__main__":
    main()
