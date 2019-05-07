#     ____________  ____      ____  ____________  ____________
#   / \           \/\   \    /\   \/\           \/\           \
#   \  \      ---  \ \   \___\_\   \ \      ---  \ \     ------\
#    \  \     _____/  \____     ____\ \     _____/  \    \___\
#     \  \    \__/  \____/ \    \__/\  \    \__/  \  \    -------\
#      \  \____\         \  \____\   \  \____\     \  \___________\
#       \/____/           \/____/     \/____/       \/___________/
#
#                    ...  █░░ --=[ CLuB ]]=-- ░░█ ...

param(
  [switch]$install=$false,
  [switch]$force=$false,
  [switch]$ignore=$false,
  [switch]$offline=$false,
  [switch]$download=$false,
  [switch]$deploy=$false,
  [switch]$skip=$false,
  [switch]$localmongodb=$false
)

$arguments = $ARGS
# map double hyphens to single for powershell use
if($arguments -eq "--install") {
  $install=$true
}
if($arguments -eq "--force") {
  $force=$true
}
if($arguments -eq "--ignore") {
  $ignore=$true
}
if($arguments -eq "--offline") {
  $offline=$true
}
if($arguments -eq "--download") {
  $download=$true
}
if($arguments -eq "--deploy") {
  $deploy=$true
}
if($arguments -eq "--skip") {
  $skip=$true
}
if($arguments -eq "--localmongodb") {
  $localmongodb=$true
}

$env:PYPE_ROOT = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Install PSWriteColor to support colorized output to terminal
if (-not (Get-Module -ListAvailable -Name "PSWriteColor")) {
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
  Install-Module -Name "PSWriteColor" -Scope CurrentUser
}

# Display spinner for running job
function Start-Progress {
  param(
    [ScriptBlock]
    $code
  )
  $scroll = "/-\|/-\|"
  $idx = 0
  $origpos = $host.UI.RawUI.CursorPosition
  $newPowerShell = [PowerShell]::Create().AddScript($code)
  $handle = $newPowerShell.BeginInvoke()
  while ($handle.IsCompleted -eq $false) {
    $host.UI.RawUI.CursorPosition = $origpos
    Write-Host $scroll[$idx] -NoNewline
    $idx++
    if($idx -ge $scroll.Length)
    {
      $idx = 0
    }
    Start-Sleep -Milliseconds 100
  }
  Write-Host ''
  $newPowerShell.EndInvoke($handle)
  $newPowerShell.Runspace.Close()
  $newPowerShell.Dispose()
}

function Activate-Venv {
  param(
    [string]$Environment
  )
  Write-Color -Text "--> ", "Activating environment [ ", $env:PYPE_ENV," ]" -Color Cyan, Gray, White, Gray
  try {
    . ("$Environment\Scripts\Activate.ps1")
  }
  catch {
    Write-Color -Text "!!! ", "Failed to activate." -Color Red, Gray
    Write-Host $_.Exception.Message
    exit 1
  }
}

function Check-Environment {
  # get current pip environment
  Write-Color -Text ">>> ", "Validating environment dependencies ... " -Color Green, Gray -NoNewLine
  $p = &{pip freeze}
  # get requirements file
  $r = Get-Content "$($env:PYPE_ROOT)\pypeapp\requirements.txt"
  if (Compare-Object -ReferenceObject $p -DifferenceObject $r) {
    # environment differs from requirements.txt
    Write-Color -Text "FAILED" -Color Yellow
    Write-Color -Text "*** ", "Environment dependencies inconsistent, fixing ... " -Color Yellow, Gray
    if ($offline -ne $true) {
      & pip install -r pypeapp\requirements.txt
    } else {
      & pip install -r pypeapp\requirements.txt -f vendor\packages
    }
  } else {
    Write-Color -Text "OK" -Color Green
  }
}

function Bootstrap-Pype {
  # ensure latest pip version
  if ($offline -ne $true)
  {
    Write-Color -Text ">>> ", "Bootstrapping Pype ... " -Color Green, Gray -NoNewLine
    Start-Progress {& python -m pip install --upgrade pip | out-null}

    # install essential dependecies
    Write-Color -Text "  - ", "Installing dependencies ... " -Color Cyan, Gray
    & pip install -r pypeapp/requirements.txt
    if ($LASTEXITCODE -ne 0) {
      Write-Color -Text "!!! ", "Installation ", "FAILED" -Color Red, Gray, Red
    }
  } else {
    # in offline mode, install all from vendor
    Write-Color -Text ">>> ", "Downloading dependencies ... " -Color Green, Gray -NoNewLine
    Start-Progress {& pip install -r pypeapp/requirements.txt -f vendor/packages | out-null}
  }
}

function Deploy-Pype {
  param(
    [bool]$Force=$false
  )
  # process pype deployment
  if ($Force -eq $true) {
    & python -m "pypeapp" --deploy --force
  } else {
    & python -m "pypeapp" --deploy
  }
}

function Validate-Pype {
  param(
    [switch]$Skip=$false
  )
  if ($Skip -eq $true) {
      & python -m "pypeapp" --validate --skipmissing
  } else {
      & python -m "pypeapp" --validate
  }

}

Write-Color -Text "*** ", "Welcome to ", "Pype", " !" -Color Green, Gray, White, Gray

# Set default environment variables if not already set
if (-not (Test-Path 'env:PYPE_ENV')) { $env:PYPE_ENV = "C:\Users\Public\pype_env2" }
if (-not (Test-Path 'env:PYPE_DEBUG')) { $env:PYPE_DEBUG = 0 }
# Add pypeapp to PYTHONPATH
$env:PYTHONPATH = "$($env:PYPE_ROOT)\pypeapp;$($env:PYTHONPATH)"

# Test if python is available
Write-Color -Text ">>> ", "Detecting python ... " -Color Green, Gray -NoNewLine
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
  Write-Color -Text "FAILED", " Python not detected" -Color Red, Yellow
  exit
}

# Test python version available
$version_command = @'
import sys
print('{0}.{1}'.format(sys.version_info[0], sys.version_info[1]))
'@

$p = &{python -c $version_command}
$m = $p -match '(\d+)\.(\d+)'
if(-not $m) {
  Write-Color -Text "FAILED", " Cannot determine version" -Color Red, Yellow
  exit
}
# We are supporting python 3.6 and up
if(($matches[1] -lt 3) -or ($matches[2] -lt 6)) {
  Write-Color -Text "FAILED", " Version [ ", $p, " ] is old and unsupported" -Color Red, Yellow, Cyan, Yellow
  exit
}

Write-Color -Text "OK" -Color Green -NoNewLine
Write-Color -Text " - version [ ", $p ," ]" -Color Gray, Cyan, Gray

# Detect mongod in PATHs
if($localmongodb -eq $true) {
  Write-Color -Text ">>> ", "Detecting MongoDB ... " -Color Green, Gray -NoNewLine
  if (-not (Get-Command "mongod" -ErrorAction SilentlyContinue)) {
    if(Test-Path 'C:\Program Files\MongoDB\Server\*\bin\mongod.exe' -PathType Leaf) {
      # we have mongo server installed on standard Windows location
      # so we can inject it to the PATH. We'll use latest version available.
      $mongoVersions = Get-ChildItem -Directory 'C:\Program Files\MongoDB\Server' | Sort-Object -Property {$_.Name -as [int]}
      if(Test-Path "C:\Program Files\MongoDB\Server\$($mongoVersions[-1])\bin\mongod.exe" -PathType Leaf) {
        $env:PATH="$($env:PATH);C:\Program Files\MongoDB\Server\$($mongoVersions[-1])\bin\"
        Write-Color -Text "OK" -Color Green
        Write-Color -Text "  - ", "auto-added from [ ", "C:\Program Files\MongoDB\Server\$($mongoVersions[-1])\bin\", " ]" -Color Cyan, Gray, White, Gray
      } else {
          Write-Color -Text "FAILED", " MongoDB not detected" -Color Red, Yellow
          Write-Color -Text "!!! ", "tried to find it on standard location [ ", "C:\Program Files\MongoDB\Server\$($mongoVersions[-1])\bin\", " ] but failed." -Color Red, Yellow, White, Yellow
          exit
      }
    } else {
      Write-Color -Text "FAILED", " MongoDB not detected" -Color Red, Yellow
      Write-Color -Text "!!! ", "'mongod' wasn't found in PATH" -Color Red, Yellow
      exit
    }

  } else {
    Write-Color -Text "OK" -Color Green
  }
}


# Detect existing venv
Write-Color -Text ">>> ", "Detecting environment ... " -Color Green, Gray -NoNewLine

$needToInstall = $false
# Does directory exist?
if (Test-Path -Path "$($env:PYPE_ENV)" -PathType Container) {
  # If so, is it empy?
  if ((Get-ChildItem $env:PYPE_ENV -Force | Select-Object -First 1 | Measure-Object).Count -eq 0) {
    $needToInstall = $true
  }
} else {
  $needToInstall = $true
}

if ($install -eq $true) {
  $needToInstall = $true
}

if ($needToInstall -eq $true) {
  if ($install -eq $true) {
    Write-Color -Text "WILL BE INSTALLED" -Color Yellow
  } else {
    Write-Color -Text "NOT FOUND" -Color Yellow
  }

  Write-Color -Text ">>> ", "Installing environment to [ ", $env:PYPE_ENV, " ]" -Color Green, Gray, White, Gray
  if($skip -eq $false) {
    if($force -eq $true) {
        & python -m "pypeapp" --install --force
    } else {
        & python -m "pypeapp" --install
    }
    if ($LASTEXITCODE -ne 0) {
      if ($LASTEXITCODE -eq 75) {
        Write-Color -Text "  - ", "If environment already exist, you can use ", "-skip", " argument to ignore it." -Color Yellow, Gray, White, Gray
      } else {
        Write-Color -Text "!!! ", "Installation failed (", $LASTEXITCODE, ")" -Color Red, Yellow, Magenta, Yellow
      }

      exit 1
    }
  } else {
    Write-Color -Text "!!! ", "Installation skipped, assuming environment is [ ", $env:PYPE_ENV, " ]" -Color Yellow, Gray, White, Gray
  }

  # activate environment
  Activate-Venv -Environment $env:PYPE_ENV

  if($skip -eq $false) {
    Bootstrap-Pype
  }
} else {
  Write-Color -Text "FOUND", " - [ ", $env:PYPE_ENV, " ]" -Color Green, Gray, White, Gray
  Activate-Venv -Environment $env:PYPE_ENV
  Check-Environment
}

# Download
# This will download pip packages to vendor/packages for later offline installation and exit
if ($download -eq $true) {
  Write-Color -Text ">>> ", "Downloading packages for offline installation ... " -Color Green, Gray
  & pip download -r pypeapp\requirements.txt -d vendor\packages --platform any
  Write-Color -Text "<-- ", "Deactivating environment ..." -Color Cyan, Gray
  deactivate
  Write-Color -Text "+++ ", "Terminating ..." -Color Magenta, Gray
  exit
}

Write-Color -Text ">>> ", "Validating ", "Pype", " deployment ... " -Color Green, Gray, White, Gray
if (($install -eq $true) -or ($deploy -eq $true) -or ($skip -eq $true)) {
    Validate-Pype -Skip
} else {
    Validate-Pype
}

if ($LASTEXITCODE -ne 0) {
  # if force set, than re-deploy
  if ($force -eq $true) {
    Write-Color -Text "!!! ", "Deployment is ", "INVALID", " - forcing re-deployment" -Color Yellow, Gray, Red, Yellow
    Write-Color -Text ">>> ", "Deploying ", "Pype", " ..." -Color Green, Gray, White, Gray
    Deploy-Pype -Force $force
    if ($LASTEXITCODE -ne 0) {
      Write-Color -Text "!!! ", "Deployment ", "FAILED" -Color Red, Yellow
      exit 1
    }
    Write-Color -Text ">>> ", "Re-validating ", "Pype", " deployment ... " -Color Green, Gray, White, Gray
    Validate-Pype
    if ($LASTEXITCODE -ne 0) {
      Write-Color -Text "!!! ", "Deployment is ", "INVALID", " - forced to ignore" -Color Yellow, Gray, Red, Yellow
      exit 1
    }
  } else {
    # if ignore set, run even if validation failed
    if ($ignore -ne $true) {
      Write-Color -Text "!!! ", "Deployment is ", "INVALID" -Color Red, Gray, Red
      Write-Color -Text "!!! ", "Pype deployment is invalid. Use ", "-force", " to re-deploy." -Color Red, Gray, White, Gray
      Write-Color -Text "... ", "Use ", "-ignore", " if you want to run Pype nevertheless at your own risk."
      exit 1
    } else {
      Write-Color -Text "!!! ", "Deployment is ", "INVALID", " - forced to ignore" -Color Yellow, Gray, Red, Yellow
    }
  }

} else {
  if ($deploy -eq $true -or $install -eq $true)
  {
    Write-Color -Text ">>> ", "Proceeding with deployment ... " -Color Green, Gray
    Deploy-Pype
    if ($LASTEXITCODE -ne 0) {
      Write-Color -Text "!!! ", "Deployment ", "FAILED" -Color Red, Yellow
      exit 1
    }
    Write-Color -Text ">>> ", "Re-validating ", "Pype", " deployment ... " -Color Green, Gray, White, Gray
    Validate-Pype
    if ($LASTEXITCODE -ne 0) {
      Write-Color -Text "!!! ", "Deployment is ", "INVALID", " - forced to ignore" -Color Yellow, Gray, Red, Yellow
      exit 1
    }
  } else {
    Write-Color -Text ">>> ", "Deployment is ", "OK" -Color Green, Gray, Green
  }
}
if ($intall -eq $true) {
    Write-Color -Text "*** ", "Installation complete. ", "Have a nice day!" -Color Green, White, Gray
    exit 0
}
Write-Color -Text ">>> ", "Running ", "pype", " ..." -Color Green, Gray, White
& python -m "pypeapp" @arguments
