"""Run from any directory; no credentials, model, network or images needed."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evaluation.harness import evaluate, human

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,required=True,help='Local result directory (never the fixture/ground-truth directory)')
args=parser.parse_args()
root=args.output.expanduser().resolve()
if root.is_relative_to(Path(__file__).resolve().parents[2]):
    parser.error('Keep generated results outside tests and ground truth')
root.mkdir(parents=True,exist_ok=True)
result=evaluate()
(root/'results.json').write_text(json.dumps(result,indent=2)+'\n')
(root/'summary.md').write_text(human(result))
print(human(result))
sys.exit(1 if result['baseline_status']!='passed' or result['counts']['failed'] or result['invocations']['subprocess_launches'] or result['invocations']['network_attempts'] else 0)
