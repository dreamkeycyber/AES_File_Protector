# AES_File_Protector
Powershell script which allows you to right click files and AES encrypt or decrypt. See README for instructions for creating registry keys.


# -------To Encrypt and Decrypt Files-------

Open Regedit

Navigate to [HKEY_CLASSES_ROOT\*\shell] >> Right Click >> New Key >> EncryptFile #Name this whatever you want it to look like when you right click

Under Encryptfile Right click >> New  Key  and name it 'command'. Click on default and copy paste the following to 'value data' (modify path as necessary):

powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Path\To\encryptdecrypt.ps1' 



Navigate to [HKEY_CLASSES_ROOT\*\shell] >> Right Click >> New Key >> DecryptFile

Under Decryptfile Right click >> New  Key  and name it 'command'. Click on default and copy paste the following to 'value data' (modify path as necessary):

powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Path\To\encryptdecrypt.ps1' -Decrypt '%1'"

#-------To Encrypt and Decrypt Folders------

Navigate to [HKEY_CLASSES_ROOT\Directory\shell] and repeat the same steps for encrypting and decrypting folders


powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Path\To\encryptdecrypt.ps1' -EncryptDir '%V'"

powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -Command "& 'C:\Path\To\encryptdecrypt.ps1' -DecryptDir '%V'"
