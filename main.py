import hashlib
import os

def calculate_md5(file_path):
    """Calculate MD5 hash value of a file."""
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def calculate_sha256(file_path):
    """Calculate SHA256 hash value of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def calculate_sha1(file_path):
    """Calculate SHA-1 hash value of a file."""
    sha1_hash = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha1_hash.update(chunk)
    return sha1_hash.hexdigest()

def calculate_vhash(file_path):
    """Calculate Vhash value of a file."""
    vhash = hashlib.blake2b()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            vhash.update(chunk)
    return vhash.hexdigest()

def calculate_authentihash(file_path):
    """Calculate Authentihash value of a file."""
    authentihash = hashlib.blake2s()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            authentihash.update(chunk)
    return authentihash.hexdigest()

def calculate_imphash(file_path):
    """Calculate Imphash value of a file."""
    import pefile
    pe = pefile.PE(file_path)
    return pe.get_imphash()

def calculate_rich_pe_header_hash(file_path):
    """Calculate Rich PE header hash value of a file."""
    import pefile
    pe = pefile.PE(file_path)
    return pe.get_rich_header_hash()

def compare_hashes(file_paths, hash_function):
    """Compare hashes of multiple files using the specified hash function."""
    hashes = {}
    for file_path in file_paths:
        hash_value = hash_function(file_path)
        hashes[file_path] = hash_value
    return hashes

def create_files_folder():
    """Create a 'files' folder if it doesn't exist."""
    if not os.path.exists('files'):
        os.makedirs('files')

def check_single_file():
    """Check the hash of a single file."""
    create_files_folder()

    file_name = input("Enter the file name (without 'files/' prefix): ").strip()
    file_path = os.path.join('files', file_name)

    if not os.path.exists(file_path):
        print("File not found.")
        return

    print("\nSelect the hash algorithm:")
    print("1. MD5")
    print("2. SHA256")
    print("3. SHA-1")
    print("4. Vhash")
    print("5. Authentihash")
    print("6. Imphash")
    print("7. Rich PE header hash")
    print("8. SSDEEP")
    print("9. TLSH")

    selection = input("Enter your choice: ").strip()
    hash_functions = {
        '1': calculate_md5,
        '2': calculate_sha256,
        '3': calculate_sha1,
        '4': calculate_vhash,
        '5': calculate_authentihash,
        '6': calculate_imphash,
        '7': calculate_rich_pe_header_hash,
    }

    if selection not in hash_functions:
        print("Invalid selection.")
        return

    hash_value = hash_functions[selection](file_path)
    print("Hash:", hash_value)

def check_multiple_files():
    """Check the hash of multiple files."""
    create_files_folder()

    print("\nSelect the hash algorithm:")
    print("1. MD5")
    print("2. SHA256")
    print("3. SHA-1")
    print("4. Vhash")
    print("5. Authentihash")
    print("6. Imphash")
    print("7. Rich PE header hash")
    print("8. TLSH")

    selection = input("Enter your choice: ").strip()
    hash_functions = {
        '1': calculate_md5,
        '2': calculate_sha256,
        '3': calculate_sha1,
        '4': calculate_vhash,
        '5': calculate_authentihash,
        '6': calculate_imphash,
        '7': calculate_rich_pe_header_hash,

    }

    if selection not in hash_functions:
        print("Invalid selection.")
        return

    num_files = int(input("Enter the number of files to compare: "))

    if num_files < 1:
        print("Please enter at least one file.")
        return

    file_names = []
    for i in range(num_files):
        file_name = input(f"Enter file name {i+1}/{num_files} (without 'files/' prefix): ").strip()
        file_names.append(file_name)

    file_paths = [os.path.join('files', file_name) for file_name in file_names]
    hash_function = hash_functions[selection]
    hashes = compare_hashes(file_paths, hash_function)

    print("\nHashes:")
    for file_path, hash_value in hashes.items():
        print("File:", file_path)
        print("Hash:", hash_value)
        print()

def compare_files():
    """Compare the hashes of multiple files."""
    create_files_folder()

    print("\nSelect the hash algorithm:")
    print("1. MD5")
    print("2. SHA256")
    print("3. SHA-1")
    print("4. Vhash")
    print("5. Authentihash")
    print("6. Imphash")
    print("7. Rich PE header hash")
    print("8. SSDEEP")
    print("9. TLSH")

    selection = input("Enter your choice: ").strip()
    hash_functions = {
        '1': calculate_md5,
        '2': calculate_sha256,
        '3': calculate_sha1,
        '4': calculate_vhash,
        '5': calculate_authentihash,
        '6': calculate_imphash,
        '7': calculate_rich_pe_header_hash,
    }

    if selection not in hash_functions:
        print("Invalid selection.")
        return

    num_files = int(input("Enter the number of files to compare: "))

    if num_files < 2:
        print("Please enter at least two files to compare.")
        return

    file_names = []
    for i in range(num_files):
        file_name = input(f"Enter file name {i+1}/{num_files} (without 'files/' prefix): ").strip()
        file_names.append(file_name)

    file_paths = [os.path.join('files', file_name) for file_name in file_names]
    hash_function = hash_functions[selection]
    hashes = compare_hashes(file_paths, hash_function)

    unique_hashes = set(hashes.values())
    if len(unique_hashes) == 1:
        print("All files have the same hash value:", unique_hashes.pop())
    else:
        print("Hashes don't match!")
        for file_path, hash_value in hashes.items():
            print("File:", file_path)
            print("Hash:", hash_value)
            print()

def main():
    while True:
        print("\nMenu:")
        print("1. Check a single file")
        print("2. Check multiple files")
        print("3. Compare hashes of multiple files")
        print("4. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            check_single_file()
        elif choice == '2':
            check_multiple_files()
        elif choice == '3':
            compare_files()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please enter a number from the menu.")

if __name__ == "__main__":
    main()
