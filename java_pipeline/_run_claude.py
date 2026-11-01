import os, sys

envfile = "/home/ahossain4/arphaH/.env"
for line in open(envfile):
    if line.startswith("ANTHROPIC_API_KEY"):
        key = line.split("=", 1)[1].strip().strip('"').strip()
        os.environ["OPENAI_API_KEY"] = key
        break
else:
    raise SystemExit("ANTHROPIC_API_KEY not found in .env")

os.environ["MEDICALJAVA_ALLOW_LLM"] = "1"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pipeline.run import main

main(sys.argv[1:])
