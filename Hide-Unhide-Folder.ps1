# Function to generate a valid AES key from a given input key or password
function Generate-AESKey {
    param(
        [string]$Key,
        [int]$KeySize = 128
    )

    # Use a key derivation function (KDF) to generate a valid key of the required length
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Key, [System.Text.Encoding]::UTF8.GetBytes($Key), 1000)
    $keyBytes = $kdf.GetBytes($KeySize / 8)

    return $keyBytes
}

# Function to encrypt a string using AES with a random IV
function Encrypt-AES {
    param(
        [string]$PlainText,
        [string]$Key,
        [int]$KeySize = 128
    )

    $keyBytes = Generate-AESKey -Key $Key -KeySize $KeySize

    $cipher = New-Object System.Security.Cryptography.AesManaged
    $cipher.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $cipher.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $cipher.GenerateIV()
    $ivBytes = $cipher.IV

    $encryptor = $cipher.CreateEncryptor($keyBytes, $ivBytes)
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

    $sw = New-Object System.IO.StreamWriter($cs)
    $sw.Write($PlainText)
    $sw.Flush()
    $cs.FlushFinalBlock()
    $ms.Flush()

    $encryptedData = $ms.ToArray()

    $ms.Close()
    $cs.Close()

    $encryptedText = [convert]::ToBase64String($ivBytes + $encryptedData)
    return $encryptedText
}

# Function to decrypt a string using AES with the extracted IV
function Decrypt-AES {
    param(
        [string]$EncryptedText,
        [string]$Key,
        [int]$KeySize = 128
    )

    $keyBytes = Generate-AESKey -Key $Key -KeySize $KeySize

    $encryptedBytes = [convert]::FromBase64String($EncryptedText)

    $ivBytes = $encryptedBytes[0..15]
    $encryptedData = $encryptedBytes[16..($encryptedBytes.Length - 1)]

    $cipher = New-Object System.Security.Cryptography.AesManaged
    $cipher.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $cipher.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $decryptor = $cipher.CreateDecryptor($keyBytes, $ivBytes)
    $ms = New-Object System.IO.MemoryStream
    $ms.Write($encryptedData, 0, $encryptedData.Length)
    $ms.Position = 0
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

    $sr = New-Object System.IO.StreamReader($cs)
    $decryptedData = $sr.ReadToEnd()
    $sr.Close()
    $cs.Close()
    $ms.Close()

    return $decryptedData
}

# Function to encrypt file name with a key (as string) using AES encryption
function Encrypt-FileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    $encryptedFileName = Encrypt-AES -PlainText $FileName -Key $Key -KeySize 128

    $SafeFileName = $encryptedFileName.Replace("/", "-")  # Replace "/" with "-"
    return $SafeFileName
}

# Function to decrypt file name with a key (as string) using AES encryption
function Decrypt-FileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EncryptedFileName,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
   
    $fileName = Decrypt-AES -EncryptedText $($EncryptedFileName.Replace("-", "/")) -Key $Key -KeySize 128
    

    return $fileName
}

function Hide-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [switch]$simulate
    )
    
    $MaxPathLength = 247

    if (Test-Path -Path $FilePath -PathType Leaf) {
        $NewFileName = Encrypt-FileName -FileName (Get-Item $FilePath).Name -Key $Key
        $NewFileName = $NewFileName + ".dat"
        $oriNewFileName = $NewFileName
        # Check if the total file path length exceeds 260 characters
        $NewFullPath = Join-Path -Path (Split-Path $FilePath) -ChildPath $NewFileName
        $existingPath = $(Split-Path $FilePath)
        if ($NewFullPath.Length -gt $MaxPathLength) {
            $NewFileNameShort = $NewFileName.Substring(0, $MaxPathLength - $existingPath.Length - 5)
            $NewFileNameShortTxt = $NewFileNameShort + ".txt"
            $NewFileNameShort = $NewFileNameShort + ".dat"
            $NewFileNameShortTxtPath = Join-Path -Path (Split-Path $FilePath) -ChildPath $NewFileNameShortTxt            
            $NewFileName = $NewFileNameShort
        }else{
            $NewFileNameShortTxtPath = ""        
        }

        # Rename the input file path with the new file name
        if($NewFileNameShortTxtPath){
            if(!$simulate){
                Set-Content -Path $(Join-Path -Path (Split-Path $FilePath) -ChildPath $NewFileNameShortTxt) -Value $oriNewFileName -Encoding UTF8
            }
            Write-Host "Created '$NewFileNameShortTxt'"
        }
        if(!$simulate){
            Rename-Item -Path $FilePath -NewName $NewFileName -Force
        }        
        Write-Host "Renamed File ['$FilePath'] to '$NewFileName'."
    } else {
        Write-Warning "File not found: $FilePath"
    }
}

function Unhide-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [switch]$simulate
    )

    if($FilePath.ToLower().EndsWith(".txt"))
    {
        return
    }
            
    if (Test-Path -Path $FilePath -PathType Leaf) {
        $parentFolderPath = Split-Path $FilePath
        $encryptedFileNameWithoutExtension = (Get-Item $FilePath).BaseName
        $encryptedTxtFileName = $encryptedFileNameWithoutExtension + ".txt"
        $encryptedTxtFilePath = Join-Path -Path $parentFolderPath -ChildPath $encryptedTxtFileName
        
        $encryptedFileName = (Get-Item $FilePath).BaseName
        if(Test-Path -Path $encryptedTxtFilePath -PathType Leaf)
        {
            $encryptedFileName = Get-Content -Path $encryptedTxtFilePath -Encoding UTF8 -Raw 
        }
        $encryptedFileNameWithoutExtension = (Get-Item $FilePath).BaseName

        $NewFileName = Decrypt-FileName -EncryptedFileName $($encryptedFileName.Replace(".dat","")) -Key $Key
        $NewFullPath = Join-Path -Path (Split-Path $FilePath) -ChildPath $NewFileName
        
        if(!$simulate){
            Rename-Item -Path $FilePath -NewName $NewFileName -Force
            if(Test-Path -Path $encryptedTxtFilePath -PathType Leaf)
            {
                Remove-Item -Path $encryptedTxtFilePath -Force 
            }
        }

        Write-Host "Recovered [$NewFullPath]"
    } else {
        Write-Warning "File not found: $FilePath"
    }
}



function Hide-Folder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,  
        [Parameter(Mandatory = $true)]
        [string]$Key,      
        [switch]$simulate
    )

    # Get all files in the directory tree
    $files = Get-ChildItem -Path $Path -File -Exclude "*.txt" -Recurse 

    # Loop through each file and get its file path without the file extension
    foreach ($file in $files) {
        $filePath = $file.FullName
        Hide-File -FilePath $filePath -Key $Key -simulate:$simulate
    }
}

function Unhide-Folder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,  
        [Parameter(Mandatory = $true)]
        [string]$Key,      
        [switch]$simulate
    )

    # Get all files in the directory tree
    $files = Get-ChildItem -Path $Path -File -Recurse

    # Loop through each file and get its file path without the file extension
    foreach ($file in $files) {
        $filePath = $file.FullName
        Unhide-File -FilePath $filePath -Key $Key -simulate:$simulate
    }
}
