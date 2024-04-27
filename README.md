# Console Exports Printer
A console application to print module exports for Windows, useful for batch scripting.  

## Example output:
```batch
>console_exports_printer.exe "%windir%\SysWOW64\d3d9.dll"

@16     0x000B8A10      <UNNAMED_EXPORT>
@17     0x000BA480      <UNNAMED_EXPORT>
@18     0x000BA4E0      <UNNAMED_EXPORT>
@19     0x000C20D0      <UNNAMED_EXPORT>
@20     0x0007A7E0      Direct3DCreate9On12
@21     0x0007A820      Direct3DCreate9On12Ex
@22     0x000B8A30      <UNNAMED_EXPORT>
@23     0x000C7BA0      <UNNAMED_EXPORT>
@24     0x000FCCC0      Direct3DShaderValidatorCreate9
@25     0x000B17D0      PSGPError
@26     0x000B1800      PSGPSampleTexture
@27     0x000BA310      D3DPERF_BeginEvent
@28     0x000BA350      D3DPERF_EndEvent
@29     0x000BA380      D3DPERF_GetStatus
@30     0x000BA3A0      D3DPERF_QueryRepeatFrame
@31     0x000BA3D0      D3DPERF_SetMarker
@32     0x000BA400      D3DPERF_SetOptions
@33     0x000BA430      D3DPERF_SetRegion
@34     0x000BA530      DebugSetLevel
@35     0x000BA560      DebugSetMute
@36     0x000BA460      Direct3D9EnableMaximizedWindowedModeShim
@37     0x000642D0      Direct3DCreate9
@38     0x00064450      Direct3DCreate9Ex
```

## Example usage in a batch script:
```batch
@echo off

:: delims is a TAB
for /f "tokens=1-3 delims=	" %%A in ('console_exports_printer.exe "%windir%\SysWOW64\d3d9.dll"') do (
    echo export ordinal = [%%~A]
    echo export RVA = [%%~B]
    
    if "%%~C"=="<UNNAMED_EXPORT>" (
        echo export has ordinal number only
    ) else (
        echo export name = "%%~C"
    )
    echo ---------------------------
    echo:
)
```

Possible output:
```
export ordinal = [@16]
export RVA = [0x000B8A10]
export has ordinal number only
---------------------------

export ordinal = [@17]
export RVA = [0x000BA480]
export has ordinal number only
---------------------------

export ordinal = [@18]
export RVA = [0x000BA4E0]
export has ordinal number only
---------------------------

export ordinal = [@19]
export RVA = [0x000C20D0]
export has ordinal number only
---------------------------

export ordinal = [@20]
export RVA = [0x0007A7E0]
export name = "Direct3DCreate9On12"
---------------------------

export ordinal = [@21]
export RVA = [0x0007A820]
export name = "Direct3DCreate9On12Ex"
---------------------------

```
