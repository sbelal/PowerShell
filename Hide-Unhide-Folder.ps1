$ErrorActionPreference = "Stop"


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

    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
        $NewFileName = Encrypt-FileName -FileName (Get-Item -LiteralPath $FilePath).Name -Key $Key
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
        }
        else {
            $NewFileNameShortTxtPath = ""        
        }

        # Rename the input file path with the new file name
        if ($NewFileNameShortTxtPath) {
            if (!$simulate) {
                Set-Content -LiteralPath $(Join-Path -Path (Split-Path $FilePath) -ChildPath $NewFileNameShortTxt) -Value $oriNewFileName -Encoding UTF8
            }
            Write-Host "Created '$NewFileNameShortTxt'"
        }
        if (!$simulate) {
            Rename-Item -LiteralPath $FilePath -NewName $NewFileName -Force
        }        
        Write-Host "Renamed File ['$FilePath'] to '$NewFileName'."
    }
    else {
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

    if ($FilePath.ToLower().EndsWith(".txt") -or $FilePath.ToLower().EndsWith("\manifest.json")) {
        return
    }
            
    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
        $parentFolderPath = Split-Path $FilePath
        $encryptedFileNameWithoutExtension = (Get-Item $FilePath).BaseName
        $encryptedTxtFileName = $encryptedFileNameWithoutExtension + ".txt"
        $encryptedTxtFilePath = Join-Path -Path $parentFolderPath -ChildPath $encryptedTxtFileName
        
        $encryptedFileName = (Get-Item $FilePath).BaseName
        if (Test-Path -LiteralPath $encryptedTxtFilePath -PathType Leaf) {
            $encryptedFileName = Get-Content -LiteralPath $encryptedTxtFilePath -Encoding UTF8 -Raw 
        }
        $encryptedFileNameWithoutExtension = (Get-Item $FilePath).BaseName

        $NewFileName = Decrypt-FileName -EncryptedFileName $($encryptedFileName.Replace(".dat", "")) -Key $Key
        $NewFullPath = Join-Path -Path (Split-Path $FilePath) -ChildPath $NewFileName
        
        if (!$simulate) {
            Rename-Item -Path $FilePath -NewName $NewFileName -Force
            if (Test-Path -LiteralPath $encryptedTxtFilePath -PathType Leaf) {
                Remove-Item -LiteralPath $encryptedTxtFilePath -Force 
            }
        }

        Write-Host "Recovered [$NewFullPath]"
    }
    else {
        Write-Warning "File not found: $FilePath"
    }
}

function Hide-Folder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderPath,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [switch]$simulate
    )
    
    $FolderPath = (Resolve-Path $FolderPath).Path.TrimEnd("\")
    $folderPaths = @()
    $folders = Get-ChildItem -LiteralPath $FolderPath -Directory -Recurse | Sort-Object FullName
    foreach ($folder in $folders) {
        $folderPaths += $folder.FullName
    }

    $manifest = @()
    For ($i = $folderPaths.Length - 1; $i -ge 0; $i--) {
        $currentFolderPath = $folderPaths[$i]
        $parentFolderPath = Split-Path -Path $currentFolderPath -Parent        
        $newFolderName = "$($i)".Trim()
        $newPathName = Join-Path -Path $parentFolderPath -ChildPath $newFolderName
        $newRelativePath = $newPathName.Replace($FolderPath, "")
        $relativePath = $currentFolderPath.Replace($FolderPath, "")
        Write-Host "Renaming folder [$relativePath] to [$newRelativePath]"
        $manifest += $(Encrypt-AES -PlainText $relativePath -Key $Key -KeySize 128)
    }
    [array]::Reverse($manifest)


    $json = ConvertTo-Json -InputObject $manifest
    if (!$simulate) {
        Set-Content -LiteralPath $($FolderPath + "\manifest.json") -Value $json -Encoding UTF8

        For ($i = $folderPaths.Length - 1; $i -ge 0; $i--) {
            $currentFolderPath = $folderPaths[$i]
            $parentFolderPath = Split-Path -Path $currentFolderPath -Parent
            $newFolderName = "$($i)".Trim()
            $newPathName = Join-Path -Path $parentFolderPath -ChildPath $newFolderName

            Rename-Item -LiteralPath $currentFolderPath -NewName $i -Force
        }
    }
    
}

function Unhide-Folder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderPath,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [switch]$simulate
    )
    
    $FolderPath = (Resolve-Path $FolderPath).Path.TrimEnd("\")

    # Read the contents of the JSON file
    $jsonContent = Get-Content $($FolderPath + "\manifest.json") -Raw

    # Convert the JSON data to a PowerShell object
    $jsonObject = ConvertFrom-Json $jsonContent

    $i = 0
    foreach ($encPath in $jsonObject) {
        $recoveredFolderPathRelative = Decrypt-AES -EncryptedText $encPath -Key $Key -KeySize 128
        $recoveredFolderPath = Join-Path -Path $FolderPath -ChildPath $recoveredFolderPathRelative
        $recoveredFolderName = Split-Path -Path $recoveredFolderPath -Leaf
        $parentFolderPath = Split-Path -Path $recoveredFolderPath -Parent
        $existingFolderPath = Join-Path -Path $parentFolderPath -ChildPath $i
        $i++
        Write-Host "[$existingFolderPath] -->  [$recoveredFolderPath]"
        
        if (!$simulate) {
            Rename-Item -LiteralPath $existingFolderPath -NewName $recoveredFolderName 
        }
    }

    if (!$simulate) {
        Remove-Item -LiteralPath $($FolderPath + "\manifest.json") -Force         
    }    
}




function Hide-Path {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,  
        [Parameter(Mandatory = $true)]
        [string]$Key,      
        [switch]$simulate
    )

    # Get all files in the directory tree
    $files = Get-ChildItem -LiteralPath $Path -File -Recurse 

    # Loop through each file and get its file path without the file extension
    foreach ($file in $files) {
        $filePath = $file.FullName
        Hide-File -FilePath $filePath -Key $Key -simulate:$simulate
    }

    Hide-Folder -FolderPath $Path -Key $Key -simulate:$simulate

}

function Unhide-Path {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,  
        [Parameter(Mandatory = $true)]
        [string]$Key,      
        [switch]$simulate
    )

    Unhide-Folder -FolderPath $Path -Key $Key -simulate:$simulate

    # Get all files in the directory tree
    $files = Get-ChildItem -LiteralPath $Path -File -Recurse

    # Loop through each file and get its file path without the file extension
    foreach ($file in $files) {
        $filePath = $file.FullName
        Write-Host "---- $filePath"
        try{
            Unhide-File -FilePath $filePath -Key $Key -simulate:$simulate
        }
        catch {
            Write-Warning "Could not unhide $filePath"
            #Write-Warning $error.message            
        }
        
    }

    
}


function unhide-now {
    Unhide-Path -Path "D:\Program Files (x86)\Citrix"  -Key trustnoonerev666ab
    Unhide-Path -Path "E:\Program Files (x86)\Citrix"  -Key trustnoonerev666ab
    Unhide-Path -Path "C:\Users\Dummy\Downloads"  -Key trustnoonerev666ab
    Unhide-Path -Path "C:\Users\Dummy\dwhelper"  -Key trustnoonerev666ab
    Unhide-Path -Path "D:\Program Files (x86)\Citrix2"  -Key trustnoonerev666ab
}

function hide-now {
    Hide-Path -Path "D:\Program Files (x86)\Citrix"  -Key trustnoonerev666ab
    Hide-Path -Path "E:\Program Files (x86)\Citrix"  -Key trustnoonerev666ab
    Hide-Path -Path "C:\Users\Dummy\Downloads"  -Key trustnoonerev666ab
    Hide-Path -Path "C:\Users\Dummy\dwhelper"  -Key trustnoonerev666ab
    Hide-Path -Path "D:\Program Files (x86)\Citrix2"  -Key trustnoonerev666ab
}