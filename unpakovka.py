import pefile, math, sys, subprocess, pyfiglet
from os.path import abspath, exists
from os import system
from colorama import Fore

def welcome():
    print(Fore.GREEN + pyfiglet.figlet_format(text='unpakovkaBBT', font='Big'))
    print(Fore.LIGHTYELLOW_EX +'Usage:', Fore.WHITE,'python unpakovka.py [-ad] file... [-o] output file...\n')
    print(Fore.LIGHTYELLOW_EX + 'Commands:')
    print(Fore.WHITE +
"""
-a      analyze file for the compression tools signatures
-d      try to decompress file (UPX and AsPack only)
-o      specify the name of output file
""")    

# File analyzing functionality (command -a)

def calculate_entropy(data):
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0
    for count in byte_counts:
        if count > 0:
            probability = float(count) / len(data)
            entropy -= probability * math.log2(probability)

    return entropy

def is_packed(pe):
    # Check for common packer signatures
    packers = ["UPX", "aspack"]
    for packer in packers:
        if packer.encode() in pe.get_data():
            return 'True,', packer

    # Check for high entropy in sections
    for section in pe.sections:
        entropy = calculate_entropy(section.get_data())
        if entropy > 6.5:
            return "Likely packed with", f"entropy: {entropy}"

    return False, ''

def analyze_file(file_path):
    try:
        pe = pefile.PE(file_path)

        if pe.FILE_HEADER.Machine == 0x14c:
            arch = "32-bit"
        elif pe.FILE_HEADER.Machine == 0x8664:
            arch = "64-bit"
        else:
            arch = "Unknown"

        data = open(file_path, "rb").read()
        entropy = calculate_entropy(data)

        packed = is_packed(pe)

        print(f"\nFile: {Fore.LIGHTBLUE_EX}{abspath(file_path)}")
        print(f"{Fore.WHITE}Architecture: {Fore.LIGHTGREEN_EX}{arch}")
        print(f"{Fore.WHITE}Packed: {Fore.GREEN if packed[0] else Fore.RED}{packed[0]} {packed[1]}")
        print(f"{Fore.WHITE}Entropy: {entropy:.4f}")

        print(f"\n{Fore.CYAN}Section Names:")
        for section in pe.sections:
            section_name = section.Name.decode(errors='ignore').strip('\x00')
            print(f"- {section_name}")
        print(Fore.RESET)

    except pefile.PEFormatError:
        print("Invalid PE file format.")
    except FileNotFoundError:
        print(Fore.RED+f'File {file_path} not exists'+Fore.WHITE)
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Decompressing functionality (command -d)


def decompress(file_path, output_file_path, packer):
    if not exists(file_path):
        print(f"Error: File not found at {file_path}")
        return

    try:
        # Construct the UPX command.  This assumes that the UPX executable
        # is named "upx" and is in the system's PATH.  You might need to
        # adjust this depending on your UPX installation.
        match packer:
            case 'UPX':
                command = f"upx.exe -d {file_path} -o {output_file_path}"
            case 'aspack':
                command = f"unipacker {file_path} -d {output_file_path}"
            case '':
                print(f'File is not packed by {Fore.LIGHTRED_EX}UPX {Fore.WHITE}or {Fore.LIGHTRED_EX}AsPack{Fore.WHITE}')
                return


        print(f"Running command: {command}")
        # Run UPX as a subprocess.
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for the process to complete and get the output.
        stdout, stderr = process.communicate()

        # Print the output from UPX.  This can be helpful for debugging.
        # print("UPX stdout:")
        # print(stdout.decode("utf-8", errors='ignore'))
        # print("UPX stderr:")
        # print(stderr.decode("utf-8", errors='ignore'))
        if 'FileAlreadyExistsException' in stderr.decode("utf-8", errors='ignore'):
            print(f"\n{Fore.RED}File {output_file_path} already exists{Fore.WHITE}")

        if process.returncode == 0:
            print(Fore.LIGHTGREEN_EX+"Successfully decompressed the file!"+Fore.WHITE)
        else:
            # print(f"Failed with exit code: {process.returncode}")
            print("Decompression may have been unsuccessful.")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("  Decompression may have been unsuccessful.")



if __name__ == "__main__":
    if sys.argv == ['unpakovka.py']:
        welcome()
    elif sys.argv == ['unpakovka.py', '-o']:
        welcome()
    else:
        match sys.argv[1]:
            case '-h':
                print("HEEEEEEEEEEEEELP!")
                sys.exit(1)
            case '-a':
                try:
                    file_path = sys.argv[2] 
                    analyze_file(file_path)
                    sys.exit(1)
                except IndexError:
                    welcome()
            case '-d':
                try:
                    file_path = sys.argv[2]
                    pe = pefile.PE(file_path)
                    packer = is_packed(pe)[1]
                    if '-o' in sys.argv:
                        output_file_path = sys.argv[sys.argv.index('-o')+1]
                        print(f"File: {Fore.LIGHTBLUE_EX}{file_path}{Fore.WHITE}")
                        decompress(file_path,output_file_path, packer)
                    else:
                        print(f"Specify the output file name {Fore.LIGHTYELLOW_EX}[-o]{Fore.WHITE}")
                    sys.exit(1)
                except IndexError:
                    welcome()
                except FileNotFoundError:
                    print(Fore.RED+f'File {file_path} not exists'+Fore.WHITE)
