@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
title ARGOS - acompanhamento semanal das fichas de meningite
rem =========================================================================
rem  ARGOS.bat  -  abre o quadro de Argos e roda o argos.R
rem  So este .bat fica na area de trabalho (ou no OneDrive). O argos.R, a
rem  figura (argos.jpg), a fonte (CascadiaMono-Regular.ttf), a planilha, o
rem  historico e o backup ficam todos na pasta argos do X:.
rem  CVE/SES-SP - versao 1.0.5 (19/11/2026)
rem =========================================================================

rem --- pasta do Argos na rede ----------------------------------------------
set "ARGOS_PASTA=X:\CCD\CVE\RESPIRATORIAS\02_MENINGITE\4_base_acompanhamentos\argos"

rem --- o argos.R: o da pasta do X: (so usa uma copia ao lado deste .bat se
rem     o X: nao tiver o argos.R) -------------------------------------------
set "ARGOS_R=%ARGOS_PASTA%\argos.R"
if not exist "%ARGOS_R%" if exist "%~dp0argos.R" set "ARGOS_R=%~dp0argos.R"
set "ARGOS_BAT=1"

rem --- a figura: na pasta do X:; se nao estiver la, o Argos baixa uma vez
rem     da internet e guarda na propria pasta do X: -------------------------
set "ARGOS_IMG="
for %%c in ("%ARGOS_PASTA%\argos.jpg" "%ARGOS_PASTA%\argos.png" "%ARGOS_PASTA%\argos*.jpg" "%~dp0argos.jpg" "%~dp0argos.png") do if not defined ARGOS_IMG if exist "%%~fc" set "ARGOS_IMG=%%~fc"
if not defined ARGOS_IMG if exist "%ARGOS_PASTA%\" set "ARGOS_IMG=%ARGOS_PASTA%\argos.jpg"
if not defined ARGOS_IMG set "ARGOS_IMG=%TEMP%\argos.jpg"

rem --- 0. a janela: fonte que mostra o olho em braille ---------------------
rem  A fonte do prompt comum (Consolas) nao tem os caracteres em braille do
rem  olho, e por isso apareciam "????". O Argos troca a fonte SO desta janela
rem  pela Cascadia Mono, que tem braille: a do Windows, se houver (Windows 11),
rem  ou o arquivo CascadiaMono-Regular.ttf da pasta argos do X: (Windows 10).
rem  O arquivo e carregado so ate o fim da sessao do Windows: nada e instalado
rem  e nada muda nas outras janelas. Se nao der, abre no Terminal do Windows,
rem  se ele existir; se nada der, o olho nao aparece (em vez dos "????").
rem  Para desligar, deixe a linha abaixo so como set "ARGOS_FONTE=".
rem  O codigo e um script do PowerShell codificado; o texto legivel dele esta
rem  no fim deste arquivo.
set "ARGOS_FONTE=dAByAHkAewAKAEEAZABkAC0AVAB5AHAAZQAgAC0AVAB5AHAAZQBEAGUAZgBpAG4AaQB0AGkAbwBuACAAJwB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzADsAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGMAbABhAHMAcwAgAEEAcgBnAG8AcwBGAG8AbgB0AGUAewBbAFMAdAByAHUAYwB0AEwAYQB5AG8AdQB0ACgATABhAHkAbwB1AHQASwBpAG4AZAAuAFMAZQBxAHUAZQBuAHQAaQBhAGwALABDAGgAYQByAFMAZQB0AD0AQwBoAGEAcgBTAGUAdAAuAFUAbgBpAGMAbwBkAGUAKQBdAHAAdQBiAGwAaQBjACAAcwB0AHIAdQBjAHQAIABGAHsAcAB1AGIAbABpAGMAIAB1AGkAbgB0ACAAYwBiADsAcAB1AGIAbABpAGMAIAB1AGkAbgB0ACAAbgA7AHAAdQBiAGwAaQBjACAAcwBoAG8AcgB0ACAAeAA7AHAAdQBiAGwAaQBjACAAcwBoAG8AcgB0ACAAeQA7AHAAdQBiAGwAaQBjACAAdQBpAG4AdAAgAGYAYQBtADsAcAB1AGIAbABpAGMAIAB1AGkAbgB0ACAAdwA7AFsATQBhAHIAcwBoAGEAbABBAHMAKABVAG4AbQBhAG4AYQBnAGUAZABUAHkAcABlAC4AQgB5AFYAYQBsAFQAUwB0AHIALABTAGkAegBlAEMAbwBuAHMAdAA9ADMAMgApAF0AcAB1AGIAbABpAGMAIABzAHQAcgBpAG4AZwAgAGYAYQBjAGUAOwB9AFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIALABDAGgAYQByAFMAZQB0AD0AQwBoAGEAcgBTAGUAdAAuAFUAbgBpAGMAbwBkAGUAKQBdAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEMAcgBlAGEAdABlAEYAaQBsAGUAVwAoAHMAdAByAGkAbgBnACAAYQAsAHUAaQBuAHQAIABiACwAdQBpAG4AdAAgAGMALABJAG4AdABQAHQAcgAgAGQALAB1AGkAbgB0ACAAZQAsAHUAaQBuAHQAIABmACwASQBuAHQAUAB0AHIAIABnACkAOwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAEMAbABvAHMAZQBIAGEAbgBkAGwAZQAoAEkAbgB0AFAAdAByACAAaAApADsAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyAC4AZABsAGwAIgAsAEMAaABhAHIAUwBlAHQAPQBDAGgAYQByAFMAZQB0AC4AVQBuAGkAYwBvAGQAZQApAF0AcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABHAGUAdABDAHUAcgByAGUAbgB0AEMAbwBuAHMAbwBsAGUARgBvAG4AdABFAHgAKABJAG4AdABQAHQAcgAgAGgALABiAG8AbwBsACAAbQAsAHIAZQBmACAARgAgAGYAKQA7AFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIALABDAGgAYQByAFMAZQB0AD0AQwBoAGEAcgBTAGUAdAAuAFUAbgBpAGMAbwBkAGUAKQBdAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAAUwBlAHQAQwB1AHIAcgBlAG4AdABDAG8AbgBzAG8AbABlAEYAbwBuAHQARQB4ACgASQBuAHQAUAB0AHIAIABoACwAYgBvAG8AbAAgAG0ALAByAGUAZgAgAEYAIABmACkAOwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBnAGQAaQAzADIALgBkAGwAbAAiACwAQwBoAGEAcgBTAGUAdAA9AEMAaABhAHIAUwBlAHQALgBVAG4AaQBjAG8AZABlACkAXQBzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAaQBuAHQAIABBAGQAZABGAG8AbgB0AFIAZQBzAG8AdQByAGMAZQBXACgAcwB0AHIAaQBuAGcAIABmACkAOwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIALABDAGgAYQByAFMAZQB0AD0AQwBoAGEAcgBTAGUAdAAuAFUAbgBpAGMAbwBkAGUAKQBdAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAFMAZQBuAGQATQBlAHMAcwBhAGcAZQBUAGkAbQBlAG8AdQB0AFcAKABJAG4AdABQAHQAcgAgAGgALAB1AGkAbgB0ACAAbQAsAEkAbgB0AFAAdAByACAAdwAsAEkAbgB0AFAAdAByACAAbAAsAHUAaQBuAHQAIABmACwAdQBpAG4AdAAgAHQALABvAHUAdAAgAEkAbgB0AFAAdAByACAAcgApADsAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGIAbwBvAGwAIABDAGEAcgByAGUAZwBhACgAcwB0AHIAaQBuAGcAIABhAHIAcQApAHsAaQBmACgAQQBkAGQARgBvAG4AdABSAGUAcwBvAHUAcgBjAGUAVwAoAGEAcgBxACkAPAAxACkAcgBlAHQAdQByAG4AIABmAGEAbABzAGUAOwBJAG4AdABQAHQAcgAgAHIAOwBTAGUAbgBkAE0AZQBzAHMAYQBnAGUAVABpAG0AZQBvAHUAdABXACgAbgBlAHcAIABJAG4AdABQAHQAcgAoADAAeABmAGYAZgBmACkALAAwAHgAMQBEACwASQBuAHQAUAB0AHIALgBaAGUAcgBvACwASQBuAHQAUAB0AHIALgBaAGUAcgBvACwAMgAsADEAMAAwADAALABvAHUAdAAgAHIAKQA7AHIAZQB0AHUAcgBuACAAdAByAHUAZQA7AH0AcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGIAbwBvAGwAIABVAHMAYQAoAHMAdAByAGkAbgBnACAAbgBvAG0AZQApAHsASQBuAHQAUAB0AHIAIABoAD0AQwByAGUAYQB0AGUARgBpAGwAZQBXACgAIgBDAE8ATgBPAFUAVAAkACIALAAwAHgAQwAwADAAMAAwADAAMAAwACwAMwAsAEkAbgB0AFAAdAByAC4AWgBlAHIAbwAsADMALAAwACwASQBuAHQAUAB0AHIALgBaAGUAcgBvACkAOwBpAGYAKABoAD0APQBuAGUAdwAgAEkAbgB0AFAAdAByACgALQAxACkAKQByAGUAdAB1AHIAbgAgAGYAYQBsAHMAZQA7AHQAcgB5AHsARgAgAGYAPQBuAGUAdwAgAEYAKAApADsAZgAuAGMAYgA9ACgAdQBpAG4AdAApAE0AYQByAHMAaABhAGwALgBTAGkAegBlAE8AZgAoAHQAeQBwAGUAbwBmACgARgApACkAOwBpAGYAKAAhAEcAZQB0AEMAdQByAHIAZQBuAHQAQwBvAG4AcwBvAGwAZQBGAG8AbgB0AEUAeAAoAGgALABmAGEAbABzAGUALAByAGUAZgAgAGYAKQApAHIAZQB0AHUAcgBuACAAZgBhAGwAcwBlADsAaQBmACgAZgAuAGYAYQBjAGUAIQA9AG4AdQBsAGwAJgAmAGYALgBmAGEAYwBlAC4AUwB0AGEAcgB0AHMAVwBpAHQAaAAoAG4AbwBtAGUAKQApAHIAZQB0AHUAcgBuACAAdAByAHUAZQA7AEYAIABuAD0AbgBlAHcAIABGACgAKQA7AG4ALgBjAGIAPQBmAC4AYwBiADsAbgAuAHgAPQAwADsAbgAuAHkAPQAoAHMAaABvAHIAdAApACgAZgAuAHkAPAAxADQAPwAxADYAOgBmAC4AeQApADsAbgAuAGYAYQBtAD0ANQA0ADsAbgAuAHcAPQA0ADAAMAA7AG4ALgBmAGEAYwBlAD0AbgBvAG0AZQA7AGkAZgAoACEAUwBlAHQAQwB1AHIAcgBlAG4AdABDAG8AbgBzAG8AbABlAEYAbwBuAHQARQB4ACgAaAAsAGYAYQBsAHMAZQAsAHIAZQBmACAAbgApACkAcgBlAHQAdQByAG4AIABmAGEAbABzAGUAOwBGACAAYwA9AG4AZQB3ACAARgAoACkAOwBjAC4AYwBiAD0AZgAuAGMAYgA7AHIAZQB0AHUAcgBuACAARwBlAHQAQwB1AHIAcgBlAG4AdABDAG8AbgBzAG8AbABlAEYAbwBuAHQARQB4ACgAaAAsAGYAYQBsAHMAZQAsAHIAZQBmACAAYwApACYAJgBjAC4AZgBhAGMAZQAhAD0AbgB1AGwAbAAmACYAYwAuAGYAYQBjAGUALgBTAHQAYQByAHQAcwBXAGkAdABoACgAbgBvAG0AZQApADsAfQBmAGkAbgBhAGwAbAB5AHsAQwBsAG8AcwBlAEgAYQBuAGQAbABlACgAaAApADsAfQB9AH0AJwAKAHQAcgB5AHsACgBBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACAAUAByAGUAcwBlAG4AdABhAHQAaQBvAG4AQwBvAHIAZQAKAGYAbwByAGUAYQBjAGgAKAAkAG4AbwBtAGUAIABpAG4AIAAnAEMAYQBzAGMAYQBkAGkAYQAgAE0AbwBuAG8AJwAsACcAQwBhAHMAYwBhAGQAaQBhACAAQwBvAGQAZQAnACkAewAKACQAZgBhAD0AWwBXAGkAbgBkAG8AdwBzAC4ATQBlAGQAaQBhAC4ARgBvAG4AdABzAF0AOgA6AFMAeQBzAHQAZQBtAEYAbwBuAHQARgBhAG0AaQBsAGkAZQBzAHwAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAewAkAF8ALgBTAG8AdQByAGMAZQAgAC0AZQBxACAAJABuAG8AbQBlAH0AfABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBGAGkAcgBzAHQAIAAxAAoAaQBmACgALQBuAG8AdAAgACQAZgBhACkAewBjAG8AbgB0AGkAbgB1AGUAfQAKAGYAbwByAGUAYQBjAGgAKAAkAHQAIABpAG4AIAAkAGYAYQAuAEcAZQB0AFQAeQBwAGUAZgBhAGMAZQBzACgAKQApAHsAJABnAD0AJABuAHUAbABsADsAaQBmACgAJAB0AC4AVAByAHkARwBlAHQARwBsAHkAcABoAFQAeQBwAGUAZgBhAGMAZQAoAFsAcgBlAGYAXQAkAGcAKQAgAC0AYQBuAGQAIAAkAGcALgBDAGgAYQByAGEAYwB0AGUAcgBUAG8ARwBsAHkAcABoAE0AYQBwAC4AQwBvAG4AdABhAGkAbgBzAEsAZQB5ACgAMAB4ADIAOABGAEYAKQApAHsAaQBmACgAWwBBAHIAZwBvAHMARgBvAG4AdABlAF0AOgA6AFUAcwBhACgAJABuAG8AbQBlACkAKQB7AGUAeABpAHQAIAAwAH0AOwBiAHIAZQBhAGsAfQB9AAoAfQAKAH0AYwBhAHQAYwBoAHsAfQAKACQAYQByAHEAPQBKAG8AaQBuAC0AUABhAHQAaAAgACQAZQBuAHYAOgBBAFIARwBPAFMAXwBQAEEAUwBUAEEAIAAnAEMAYQBzAGMAYQBkAGkAYQBNAG8AbgBvAC0AUgBlAGcAdQBsAGEAcgAuAHQAdABmACcACgBpAGYAKABUAGUAcwB0AC0AUABhAHQAaAAgACQAYQByAHEAKQB7AAoAaQBmACgAWwBBAHIAZwBvAHMARgBvAG4AdABlAF0AOgA6AEMAYQByAHIAZQBnAGEAKAAkAGEAcgBxACkAIAAtAGEAbgBkACAAWwBBAHIAZwBvAHMARgBvAG4AdABlAF0AOgA6AFUAcwBhACgAJwBDAGEAcwBjAGEAZABpAGEAIABNAG8AbgBvACcAKQApAHsAZQB4AGkAdAAgADAAfQAKACQAdABtAHAAPQBKAG8AaQBuAC0AUABhAHQAaAAgACQAZQBuAHYAOgBUAEUATQBQACAAJwBhAHIAZwBvAHMAXwBDAGEAcwBjAGEAZABpAGEATQBvAG4AbwAtAFIAZQBnAHUAbABhAHIALgB0AHQAZgAnAAoAaQBmACgALQBuAG8AdAAoAFQAZQBzAHQALQBQAGEAdABoACAAJAB0AG0AcAApACkAewBDAG8AcAB5AC0ASQB0AGUAbQAgACQAYQByAHEAIAAkAHQAbQBwAH0ACgBpAGYAKABbAEEAcgBnAG8AcwBGAG8AbgB0AGUAXQA6ADoAQwBhAHIAcgBlAGcAYQAoACQAdABtAHAAKQAgAC0AYQBuAGQAIABbAEEAcgBnAG8AcwBGAG8AbgB0AGUAXQA6ADoAVQBzAGEAKAAnAEMAYQBzAGMAYQBkAGkAYQAgAE0AbwBuAG8AJwApACkAewBlAHgAaQB0ACAAMAB9AAoAfQAKAH0AYwBhAHQAYwBoAHsAfQAKAGUAeABpAHQAIAAxAAoA"
set "ARGOS_BRAILLE="
if defined WT_SESSION set "ARGOS_BRAILLE=1"
if not defined ARGOS_BRAILLE if defined ARGOS_FONTE powershell -NoProfile -NonInteractive -EncodedCommand %ARGOS_FONTE% >nul 2>&1 && set "ARGOS_BRAILLE=1"
if defined ARGOS_BRAILLE goto :janela_ok
if not defined ARGOS_FONTE goto :janela_ok
where wt.exe >nul 2>&1 || goto :janela_ok
start "" wt.exe cmd /c "%~f0" && exit /b
:janela_ok

rem --- 1. o quadro: Mercurio embalando Argos para que durma (Gandolfi) ------
if not exist "%ARGOS_IMG%" powershell -NoProfile -Command "try{[Net.ServicePointManager]::SecurityProtocol='Tls12'; $w=New-Object Net.WebClient; $w.Headers.Add('User-Agent','Argos-CVE/1.0'); if($w.Proxy){$w.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials}; $w.DownloadFile('https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/Ubaldo_Gandolfi_-_Mercury_Lulling_Argus_to_Sleep%%2C_1770-1775.jpg/960px-Ubaldo_Gandolfi_-_Mercury_Lulling_Argus_to_Sleep%%2C_1770-1775.jpg', $env:ARGOS_IMG)}catch{}" >nul 2>&1
set "ARGOS_PS=Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
set "ARGOS_PS=%ARGOS_PS% $i=[Drawing.Image]::FromFile($env:ARGOS_IMG);"
set "ARGOS_PS=%ARGOS_PS% $a=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea;"
set "ARGOS_PS=%ARGOS_PS% $h=[Math]::Min(660,$a.Height-80); $w=[int]($h*$i.Width/$i.Height);"
set "ARGOS_PS=%ARGOS_PS% $f=New-Object Windows.Forms.Form; $f.FormBorderStyle='None'; $f.StartPosition='CenterScreen';"
set "ARGOS_PS=%ARGOS_PS% $f.TopMost=$true; $f.ShowInTaskbar=$false; $f.BackColor=[Drawing.Color]::FromArgb(14,22,38);"
set "ARGOS_PS=%ARGOS_PS% $f.ClientSize=New-Object Drawing.Size(($w+420),$h);"
set "ARGOS_PS=%ARGOS_PS% $p=New-Object Windows.Forms.PictureBox; $p.Image=$i; $p.SizeMode='Zoom'; $p.SetBounds(0,0,$w,$h); $f.Controls.Add($p);"
set "ARGOS_PS=%ARGOS_PS% function L($t,$y,$z,$s,$c,$hh){$l=New-Object Windows.Forms.Label; $l.Text=$t; $l.ForeColor=$c;"
set "ARGOS_PS=%ARGOS_PS%  $l.Font=New-Object Drawing.Font('Georgia',$z,[Drawing.FontStyle]$s); $l.SetBounds(($w+32),$y,370,$hh);"
set "ARGOS_PS=%ARGOS_PS%  $l.Add_Click({$f.Close()}); $f.Controls.Add($l)};"
set "ARGOS_PS=%ARGOS_PS% $o=[Drawing.Color]::FromArgb(212,175,55); $b=[Drawing.Color]::FromArgb(232,232,232); $c=[Drawing.Color]::FromArgb(150,160,178);"
set "ARGOS_PS=%ARGOS_PS% L 'ARGOS' 56 42 'Bold' $o 76; L 'P A N O P T E S' 134 12 'Regular' $o 28;"
set "ARGOS_PS=%ARGOS_PS% L 'acompanhamento semanal das fichas de meningite' 176 13 'Regular' $b 56;"
set "ARGOS_PS=%ARGOS_PS% L '«cetera servabant atque in statione manebant»' 262 11 'Italic' $b 48;"
set "ARGOS_PS=%ARGOS_PS% L 'os outros olhos vigiavam e permaneciam em seu posto  (Ovídio, Metamorfoses I, 627)' 312 9 'Regular' $c 44;"
set "ARGOS_PS=%ARGOS_PS% L 'Os cem olhos estão abertos: o R está lendo a base do Sinan e montando a planilha...' ($h-190) 10 'Regular' $b 52;"
set "ARGOS_PS=%ARGOS_PS% L 'Ubaldo Gandolfi, Mercúrio embalando Argos para que durma (c. 1770-1775). Domínio público.' ($h-112) 8 'Italic' $c 44;"
set "ARGOS_PS=%ARGOS_PS% L 'CVE/SES-SP  ·  clique para fechar' ($h-46) 8 'Regular' $c 24;"
set "ARGOS_PS=%ARGOS_PS% $p.Add_Click({$f.Close()}); $f.Add_Click({$f.Close()});"
set "ARGOS_PS=%ARGOS_PS% $t=New-Object Windows.Forms.Timer; $t.Interval=10000; $t.Add_Tick({$t.Stop(); $f.Close()}); $t.Start();"
set "ARGOS_PS=%ARGOS_PS% [Windows.Forms.Application]::Run($f)"
if exist "%ARGOS_IMG%" start "" /min powershell -NoProfile -STA -WindowStyle Hidden -Command "%ARGOS_PS%"

echo.
echo    =====================================================================
echo      A R G O S   -   acompanhamento semanal das fichas de meningite
echo    =====================================================================
echo.

rem --- 2. acha o R ---------------------------------------------------------
rem  O Argos procura todas as versoes do R instaladas neste computador (registro do
rem  Windows, pastas comuns e PATH), da mais nova para a mais antiga, e usa a primeira
rem  que ja tem os pacotes dele (e que seja 4.2 ou mais nova, por causa dos acentos). Se nenhuma tiver, usa a mais nova e o argos.R instala
rem  os pacotes na pasta do usuario.
rem  Para usar uma versao especifica, coloque o caminho do Rscript.exe aqui, ex.:
rem  set "ARGOS_RSCRIPT=C:\Program Files\R\R-4.5.1\bin\Rscript.exe"
set "ARGOS_RSCRIPT="
set "RSCRIPT="
set "R_OK="
set "R_TESTE=ok <- getRversion() >= '4.2.0' && all(vapply(c('dplyr','lubridate','stringi','openxlsx'), requireNamespace, logical(1), quietly = TRUE)); quit(status = if (ok) 0 else 1)"
if defined ARGOS_RSCRIPT if exist "%ARGOS_RSCRIPT%" set "RSCRIPT=%ARGOS_RSCRIPT%"
if defined RSCRIPT goto :r_escolhido
echo    Procurando o R com os pacotes do Argos...
set "ARGOS_LISTA=%TEMP%\argos_r_%RANDOM%.txt"
type nul > "%ARGOS_LISTA%"
for %%k in ("HKLM\SOFTWARE\R-core\R" "HKLM\SOFTWARE\R-core\R64" "HKCU\SOFTWARE\R-core\R" "HKCU\SOFTWARE\R-core\R64" "HKLM\SOFTWARE\WOW6432Node\R-core\R") do (
  for /f "tokens=2,*" %%a in ('reg query %%k /s /v InstallPath 2^>nul ^| find "InstallPath"') do (
    if exist "%%b\bin\Rscript.exe" for %%v in ("%%b") do echo %%~nxv^|%%b\bin\Rscript.exe>>"%ARGOS_LISTA%"
  )
)
for %%p in ("%ProgramFiles%\R" "%LOCALAPPDATA%\Programs\R" "%USERPROFILE%\Documents\R" "%USERPROFILE%\R" "C:\R") do (
  if exist "%%~p" for /d %%d in ("%%~p\R-*") do if exist "%%d\bin\Rscript.exe" echo %%~nxd^|%%d\bin\Rscript.exe>>"%ARGOS_LISTA%"
)
for /f "delims=" %%i in ('where Rscript.exe 2^>nul') do for %%v in ("%%~dpi..") do for %%w in ("%%~fv") do echo %%~nxw^|%%i>>"%ARGOS_LISTA%"
rem  cada linha da lista: R-x.y.z^|caminho do Rscript.exe; testa da versao mais nova para a mais antiga
for /f "usebackq tokens=1,* delims=|" %%a in (`sort /R "%ARGOS_LISTA%"`) do (
  if not defined RSCRIPT (
    "%%b" -e "%R_TESTE%" >nul 2>&1 && set "RSCRIPT=%%b"
  )
)
if defined RSCRIPT set "R_OK=1"
rem  nenhuma versao tem os pacotes: usa a mais nova (o argos.R instala o que faltar)
if not defined RSCRIPT for /f "usebackq tokens=1,* delims=|" %%a in (`sort /R "%ARGOS_LISTA%"`) do if not defined RSCRIPT set "RSCRIPT=%%b"
del "%ARGOS_LISTA%" >nul 2>&1
:r_escolhido
if not defined RSCRIPT goto :sem_r
if not exist "%ARGOS_R%" goto :sem_script

rem --- 3. roda o Argos -----------------------------------------------------
echo    R: %RSCRIPT%
if not defined R_OK if not defined ARGOS_RSCRIPT echo       - nenhum R deste computador tem todos os pacotes; o Argos vai tentar instala-los
echo    Script: %ARGOS_R%
echo.
"%RSCRIPT%" "%ARGOS_R%"
set "ERRO=%ERRORLEVEL%"
echo.
if "%ERRO%"=="0" goto :fim_ok
echo    [!] O Argos terminou com erro - codigo %ERRO%. Veja as mensagens acima.
goto :fim

:fim_ok
echo    Pronto. A planilha foi salva e aberta no Excel.
goto :fim

:sem_r
echo    [!] Nao encontrei o R (Rscript.exe) neste computador.
echo        Instale o R ou ajuste o caminho no inicio deste arquivo.
goto :fim

:sem_script
echo    [!] Nao encontrei o argos.R (o X: esta conectado?). Ele deve ficar em:
echo        %ARGOS_PASTA%\
goto :fim

:fim
echo.
pause
endlocal
exit /b

rem =========================================================================
rem  (o Windows nao le daqui para baixo)
rem  Texto do ARGOS_FONTE: script do PowerShell que troca a fonte desta janela
rem  por uma que tem braille. Para gerar o codigo de novo, no PowerShell:
rem  [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((Get-Content argos_fonte.ps1 -Raw)))
rem =========================================================================
rem   try{
rem   Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class ArgosFonte{[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]public struct F{public uint cb;public uint n;public short x;public short y;public uint fam;public uint w;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string face;}[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern IntPtr CreateFileW(string a,uint b,uint c,IntPtr d,uint e,uint f,IntPtr g);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool GetCurrentConsoleFontEx(IntPtr h,bool m,ref F f);[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool SetCurrentConsoleFontEx(IntPtr h,bool m,ref F f);[DllImport("gdi32.dll",CharSet=CharSet.Unicode)]static extern int AddFontResourceW(string f);[DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern IntPtr SendMessageTimeoutW(IntPtr h,uint m,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r);public static bool Carrega(string arq){if(AddFontResourceW(arq)<1)return false;IntPtr r;SendMessageTimeoutW(new IntPtr(0xffff),0x1D,IntPtr.Zero,IntPtr.Zero,2,1000,out r);return true;}public static bool Usa(string nome){IntPtr h=CreateFileW("CONOUT$",0xC0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);if(h==new IntPtr(-1))return false;try{F f=new F();f.cb=(uint)Marshal.SizeOf(typeof(F));if(!GetCurrentConsoleFontEx(h,false,ref f))return false;if(f.face!=null&&f.face.StartsWith(nome))return true;F n=new F();n.cb=f.cb;n.x=0;n.y=(short)(f.y<14?16:f.y);n.fam=54;n.w=400;n.face=nome;if(!SetCurrentConsoleFontEx(h,false,ref n))return false;F c=new F();c.cb=f.cb;return GetCurrentConsoleFontEx(h,false,ref c)&&c.face!=null&&c.face.StartsWith(nome);}finally{CloseHandle(h);}}}'
rem   try{
rem   Add-Type -AssemblyName PresentationCore
rem   foreach($nome in 'Cascadia Mono','Cascadia Code'){
rem   $fa=[Windows.Media.Fonts]::SystemFontFamilies|Where-Object{$_.Source -eq $nome}|Select-Object -First 1
rem   if(-not $fa){continue}
rem   foreach($t in $fa.GetTypefaces()){$g=$null;if($t.TryGetGlyphTypeface([ref]$g) -and $g.CharacterToGlyphMap.ContainsKey(0x28FF)){if([ArgosFonte]::Usa($nome)){exit 0};break}}
rem   }
rem   }catch{}
rem   $arq=Join-Path $env:ARGOS_PASTA 'CascadiaMono-Regular.ttf'
rem   if(Test-Path $arq){
rem   if([ArgosFonte]::Carrega($arq) -and [ArgosFonte]::Usa('Cascadia Mono')){exit 0}
rem   $tmp=Join-Path $env:TEMP 'argos_CascadiaMono-Regular.ttf'
rem   if(-not(Test-Path $tmp)){Copy-Item $arq $tmp}
rem   if([ArgosFonte]::Carrega($tmp) -and [ArgosFonte]::Usa('Cascadia Mono')){exit 0}
rem   }
rem   }catch{}
rem   exit 1