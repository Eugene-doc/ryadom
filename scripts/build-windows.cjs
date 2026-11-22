'use strict';
const fs=require('node:fs');const path=require('node:path');const {execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..');process.chdir(root);
const version=JSON.parse(fs.readFileSync('package.json','utf8')).version;
const output=`dist/Ryadom-Windows-${version}.exe`;
fs.mkdirSync('dist',{recursive:true});fs.mkdirSync('.build',{recursive:true});
const assets=Object.fromEntries(['index.html','style.css','app.js','e2ee.js','icon.svg'].map(name=>[name,path.join(root,'public',name)]));
const config={main:path.join(root,'server.cjs'),output:path.join(root,'.build','RyadomHost.exe'),disableExperimentalSEAWarning:true,useCodeCache:false,execArgvExtension:'none',assets};
fs.writeFileSync('.build/sea-config.json',JSON.stringify(config,null,2));
execFileSync(process.execPath,['--build-sea','.build/sea-config.json'],{stdio:'inherit'});
fs.writeFileSync('.build/host.sha256',require('node:crypto').createHash('sha256').update(fs.readFileSync('.build/RyadomHost.exe')).digest('hex'));
execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/create-icon.ps1'],{stdio:'inherit'});
const webview=path.join(root,'.tools','webview2','package');
if(!fs.existsSync(path.join(webview,'lib','net462','Microsoft.Web.WebView2.Core.dll')))execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(root,'scripts','fetch-webview2.ps1')],{stdio:'inherit'});
const staging=path.join(require('node:os').tmpdir(),'RyadomWindowsBuild');fs.mkdirSync(staging,{recursive:true});
for(const source of ['.build/RyadomHost.exe','.build/host.sha256','.build/ryadom.ico','windows/Launcher.cs','windows/ChatWindow.cs','windows/AssemblyInfo.cs','windows/LanTransport.cs','windows/RolePicker.cs','windows/Firewall.cs','windows/TlsIdentity.cs','windows/DeviceIdentity.cs','windows/SingleInstanceActivation.cs','windows/LoopbackActivation.cs','windows/ActivationRouter.cs'])fs.copyFileSync(source,path.join(staging,path.basename(source)));
const coreDll=path.join(webview,'lib','net462','Microsoft.Web.WebView2.Core.dll');
const winformsDll=path.join(webview,'lib','net462','Microsoft.Web.WebView2.WinForms.dll');
const loaderDll=path.join(webview,'runtimes','win-x64','native','WebView2Loader.dll');
execFileSync('C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe',['/nologo','/codepage:65001','/target:winexe','/optimize+','/out:Ryadom-Windows.exe','/win32icon:ryadom.ico','/reference:System.dll','/reference:System.Core.dll','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Management.dll','/reference:'+coreDll,'/reference:'+winformsDll,'/resource:RyadomHost.exe,Host','/resource:host.sha256,HostHash','/resource:'+coreDll+',WebView2.Core.dll','/resource:'+winformsDll+',WebView2.WinForms.dll','/resource:'+loaderDll+',WebView2Loader.dll','Launcher.cs','ChatWindow.cs','AssemblyInfo.cs','LanTransport.cs','RolePicker.cs','Firewall.cs','TlsIdentity.cs','DeviceIdentity.cs','SingleInstanceActivation.cs','LoopbackActivation.cs','ActivationRouter.cs'],{stdio:'inherit',cwd:staging});
fs.copyFileSync(path.join(staging,'Ryadom-Windows.exe'),output);
if(process.env.RYADOM_SIGN_RELEASE==='1'){execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/sign-release.ps1','-DistDir','dist'],{stdio:'inherit'});}
else{console.log('Совет: для подписи релиза выполните scripts/sign-release.ps1 или сборку с RYADOM_SIGN_RELEASE=1.');}
console.log(`Готово: ${output}`);
