"""Optional Ghidra headless exporter. Raw pseudocode is never executed."""
import argparse, json, os, pathlib, re, shutil, subprocess, tempfile


def export(binary, function, *, headless=None, timeout=120, decompile_timeout=30):
    binary=pathlib.Path(binary).resolve(strict=True)
    if not binary.is_file() or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',function):
        raise ValueError('expected regular input file and simple named function')
    if not (1<=decompile_timeout<=timeout<=3600):raise ValueError('invalid timeouts')
    executable=headless or os.environ.get('GHIDRA_HEADLESS') or shutil.which('analyzeHeadless')
    if not executable:return {'status':'DEPENDENCY_MISSING','reason':'set GHIDRA_HEADLESS to support/analyzeHeadless'}
    executable=shutil.which(str(executable))
    if not executable:return {'status':'DEPENDENCY_MISSING','reason':'headless launcher not executable'}
    scripts=pathlib.Path(__file__).parent/'ghidra_scripts'
    with tempfile.TemporaryDirectory(prefix='chrono-ghidra-') as d:
        root=pathlib.Path(d);project=root/'project';project.mkdir();out=root/'export';out.mkdir()
        cmd=[executable,str(project),'Chrono','-import',str(binary),'-scriptPath',str(scripts),'-postScript','ChronoExport.java',function,str(out),str(decompile_timeout),'-analysisTimeoutPerFile',str(timeout),'-deleteProject']
        try:r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)
        except subprocess.TimeoutExpired:return {'status':'TIMEOUT'}
        except OSError as e:return {'status':'LAUNCH_FAILED','reason':str(e)}
        code=out/'decompiled.c';entry=out/'entry.txt'
        if r.returncode or not code.is_file() or not entry.is_file():
            return {'status':'EXPORT_FAILED','returncode':r.returncode,'log_tail':(r.stdout+'\n'+r.stderr)[-4000:]}
        text=code.read_text(encoding='utf-8');address=entry.read_text(encoding='utf-8').strip()
        if not text.strip() or not address:return {'status':'EXPORT_FAILED','reason':'empty output'}
        return {'status':'RAW_PSEUDOCODE','function':function,'entry':address,'code':text,'verified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('function');p.add_argument('--headless');p.add_argument('--timeout',type=int,default=120);a=p.parse_args()
    print(json.dumps(export(a.binary,a.function,headless=a.headless,timeout=a.timeout),indent=2))
