# Function to encrypt a file using AES encryption
function Protect-AESFile {
    Param(
        [Byte[]]$FileBytes,
        [String]$Password,
        [Byte[]]$Salt,
        [String]$HashAlgorithm = "SHA512"
    )

    if (-not $Salt) {
        $Salt = New-Object byte[] 16
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Salt)
    }

    $PasswordBytes = [System.Text.Encoding]::ASCII.GetBytes($Password)

    [System.IO.MemoryStream]$MemoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
    $AES.KeySize = 256
    $AES.BlockSize = 128
    [System.Security.Cryptography.Rfc2898DeriveBytes]$Key = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PasswordBytes, $Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::$HashAlgorithm)
    $AES.Key = $Key.GetBytes($AES.KeySize / 8)
    $AES.IV = $Key.GetBytes($AES.BlockSize / 8)
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $AES.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

    try {
        $CryptoStream.Write($FileBytes, 0, $FileBytes.Length)
        $CryptoStream.Close()
    } catch {
        Write-Error "Error occurred while encrypting file."
        return $null
    }

    $EncryptedBytes = $MemoryStream.ToArray()
    return $Salt + $EncryptedBytes
}

# Function to decrypt a file using AES decryption
function Unprotect-AESFile {
    Param(
        [Byte[]]$FileBytes,
        [String]$Password,
        [String]$HashAlgorithm = "SHA512"
    )

    $Salt = $FileBytes[0..15]
    $EncryptedBytes = $FileBytes[16..($FileBytes.Length - 1)]

    $PasswordBytes = [System.Text.Encoding]::ASCII.GetBytes($Password)
    [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
    $AES.KeySize = 256
    $AES.BlockSize = 128
    [System.Security.Cryptography.Rfc2898DeriveBytes]$Key = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PasswordBytes, $Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::$HashAlgorithm)
    $AES.Key = $Key.GetBytes($AES.KeySize / 8)
    $AES.IV = $Key.GetBytes($AES.BlockSize / 8)
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC

    [System.IO.MemoryStream]$MemoryStream = New-Object System.IO.MemoryStream
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $AES.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

    try {
        $CryptoStream.Write($EncryptedBytes, 0, $EncryptedBytes.Length)
        $CryptoStream.Close()
    } catch {
        Write-Error "Error occurred while decrypting file."
        return $null
    }

    return $MemoryStream.ToArray()
}

# Function to encrypt a file
function Encrypt-File {
    Param(
        [string]$FilePath,
        [string]$Password
    )

    Write-Host "Encrypting file: $FilePath"

    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $EncryptedBytes = Protect-AESFile -FileBytes $FileBytes -Password $Password
    if ($EncryptedBytes) {
        [System.IO.File]::WriteAllBytes($FilePath, $EncryptedBytes)
        Write-Host "File encrypted successfully."
    } else {
        Write-Host "Failed to encrypt the file."
    }
}

# Function to decrypt a file
function Decrypt-File {
    Param(
        [string]$FilePath,
        [string]$Password
    )

    Write-Host "Decrypting file: $FilePath"

    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $DecryptedBytes = Unprotect-AESFile -FileBytes $FileBytes -Password $Password
    if ($DecryptedBytes) {
        [System.IO.File]::WriteAllBytes($FilePath, $DecryptedBytes)
        Write-Host "File decrypted successfully."
    } else {
        Write-Host "Failed to decrypt the file."
    }
}

# Function to encrypt all files in a directory
function Encrypt-FilesInDirectory {
    Param(
        [string]$DirectoryPath,
        [string]$Password
    )

    Write-Host "Encrypting all files in directory: $DirectoryPath"

    Get-ChildItem -Path $DirectoryPath -File | ForEach-Object {
        $FilePath = $_.FullName
        Encrypt-File -FilePath $FilePath -Password $Password
    }
}

# Function to decrypt all files in a directory
function Decrypt-FilesInDirectory {
    Param(
        [string]$DirectoryPath,
        [string]$Password
    )

    Write-Host "Decrypting all files in directory: $DirectoryPath"

    Get-ChildItem -Path $DirectoryPath -File | ForEach-Object {
        $FilePath = $_.FullName
        Decrypt-File -FilePath $FilePath -Password $Password
    }
}

# ---- Additional Code for Context Menu Integration ----

# Fetch the file path and action from command-line arguments
$Action = $args[0]
$FilePath = $args[1]

# Function to prompt for a password securely
function Get-SecurePassword {
    param (
        [string]$PromptMessage
    )
    Write-Host $PromptMessage -ForegroundColor Green
    $Password = Read-Host -AsSecureString
    return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
}

# Function to get and confirm the password for encryption
function Get-ConfirmedPassword {
    do {
        $Password1 = Get-SecurePassword "Enter password to encrypt file:"
        $Password2 = Get-SecurePassword "Confirm password to encrypt file:"

        if ($Password1 -ne $Password2) {
            Write-Host "Passwords do not match. Please try again." -ForegroundColor Red
        }
    } while ($Password1 -ne $Password2)

    return $Password1
}

# Check if the first argument is -Encrypt, -Decrypt, -EncryptDir, or -DecryptDir
if ($Action -eq "-Encrypt") {
    # Get and confirm password for encryption
    $Password = Get-ConfirmedPassword
    Encrypt-File -FilePath $FilePath -Password $Password
} elseif ($Action -eq "-Decrypt") {
    # Prompt for password for decryption
    $Password = Get-SecurePassword "Enter password to decrypt file:"
    Decrypt-File -FilePath $FilePath -Password $Password
} elseif ($Action -eq "-EncryptDir") {
    # Get and confirm password for encryption
    $Password = Get-ConfirmedPassword
    Encrypt-FilesInDirectory -DirectoryPath $FilePath -Password $Password
} elseif ($Action -eq "-DecryptDir") {
    # Prompt for password for decryption
    $Password = Get-SecurePassword "Enter password to decrypt file:"
    Decrypt-FilesInDirectory -DirectoryPath $FilePath -Password $Password
} else {
    Write-Host "Invalid operation. Please use '-Encrypt', '-Decrypt', '-EncryptDir', or '-DecryptDir' in the context menu command."
}
