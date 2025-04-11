import os

def read_file(file_name):
    # Insecure: User input is used directly without validation
    base_directory = "/safe_directory/"
    file_path = base_directory + file_name

    # Unsafely accessing the file without sanitizing user input
    with open(file_path, "r") as f:
        return f.read()

# This could allow an attacker to input something like "../../etc/passwd"
user_input = input("Enter the file name to read: ")
print(read_file(user_input))  # Vulnerable to directory traversal