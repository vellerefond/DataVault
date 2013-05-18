DataVault
=========

A tool to encrypt and decrypt files using Serpent in CBC mode, written in C#.

Features:

	* Uses the BouncyCastle (http://www.bouncycastle.org/) Cryptographic C# library.
	* Makes use Serpent in CBC mode.
	* The key is hashed using the Whirlpool hash algorithm.

Usage:

DataVault.exe ([-h] | [-p] (-e | -d) [source_file_path] [destination_file_path])

	-h                   	Display this help message.
	-p                   	Preserve the source file.
	-e                   	Encrypt the source file (must not be used with -d).
	-d                   	Decrypt the source file (must not be used with -e).
	source_file_path     	The path to the source file to encrypt/decrypt.
	destination_file_path	The path to the destination file.

Notes:

	* If the arguments are "[-p] -e" or "[-p] -d" a file chooser will be invoked to select the source and destination files.
	* When encrypting and the destination file is not provided, the suffix ".encrypted" will be appended to the source file after the encryption process.
	* If the destination file is ommited, it will be the same as the source file with the suffix ".encrypted" stripped.
	* If the destination file exists or the suffix ".encrypted" does not exist in the name of the source file, the suffix ".decrypted" will be appended to the source file after the decryption process.