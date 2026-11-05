"""Explicit operational Makefile helpers, never used by default help.
Copyright (c) 2026 Hayk Jomardyan - Lolisoft. Repository license applies.
"""
from pathlib import Path
from datetime import datetime,timezone
import os,re,shutil,subprocess,sys,time,zipfile
ROOT=Path(__file__).resolve().parents[1]
def reports(value):
    raw=Path(value);path=(ROOT/raw).resolve()
    if path!=ROOT/'reports' and ROOT/'reports' not in path.parents:raise SystemExit('Report/archive paths must remain inside reports/')
    for parent in (ROOT/raw,*(ROOT/raw).parents):
        if parent==ROOT:break
        if parent.is_symlink() or getattr(parent,'is_junction',lambda:False)():raise SystemExit('Refusing redirected report path')
    return path
def generated(folder):return [p for p in folder.iterdir() if p.is_file() and not p.is_symlink() and re.fullmatch(r'cyberswiss_[0-9_]+\.(json|csv|html|txt|sarif|md)',p.name)]
action=sys.argv[1];args=sys.argv[2:]
if action=='confirm':
    if args!=['1']:raise SystemExit('Set the documented confirmation variable to 1 for this destructive operation')
elif action=='require-value':
    if len(args)!=1 or not args[0].strip():raise SystemExit('Set the required target option before running this command')
elif action=='scan-ids':
    if not args or not args[0].strip():raise SystemExit('Set SCRIPTS to explicit script IDs')
    ids=args[0].split()
    if not all(re.fullmatch(r'[LW][0-9]+',s) for s in ids):raise SystemExit('Invalid script ID')
    raise SystemExit(subprocess.call([sys.executable,str(ROOT/'common/runner.py'),'--scripts',*ids,*args[1:]],cwd=ROOT))
elif action=='check-env':
    tool='powershell' if os.name=='nt' else 'bash'
    if not shutil.which(tool):raise SystemExit('Missing script runtime: '+tool)
elif action=='install-runtime':
    if not sys.platform.startswith('linux'):raise SystemExit('OS-level installer is supported only on Linux')
    raise SystemExit(subprocess.call(['bash','setup/install_runtime_linux.sh','--optional','--yes'],cwd=ROOT))
elif action=='shell-lint':
    files=sorted((ROOT/'linux').glob('*.sh'))+[ROOT/'common/json_fields.bash']
    raise SystemExit(subprocess.call([args[0],'--severity=warning',*map(str,files)],cwd=ROOT))
elif action=='archive':
    folder,target=map(reports,args);files=generated(folder)
    if not files:raise SystemExit('No generated reports found; no empty archive created')
    target.mkdir(parents=True,exist_ok=True)
    archive=target/('cyberswiss_archive_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')+'.zip')
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED) as z:
        for p in files:z.write(p,p.name)
elif action=='archive-clean':
    folder=reports(args[0])
    if folder.exists():
        for p in folder.glob('cyberswiss_archive_*.zip'):
            if p.is_file() and not p.is_symlink() and p.stat().st_mtime<time.time()-30*86400:p.unlink()
elif action=='clean-reports':
    folder=reports(args[0])
    if folder.exists():
        tracked=set(subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0'))
        files=generated(folder)
        if any(p.relative_to(ROOT).as_posix() in tracked for p in files):raise SystemExit('Refusing tracked report fixtures')
        for p in files:p.unlink()
elif action=='db-clean':
    p=reports('reports/cyberswiss.db')
    if p.exists():p.unlink()
else:raise SystemExit('Unknown Makefile operational helper')
