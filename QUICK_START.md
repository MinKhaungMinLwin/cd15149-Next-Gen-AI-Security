# Quick Start

Everything runs inside this lab. You do not install anything, and you do not need your
own API keys or cloud account.

## 1. Check your environment

```bash
cd /voc/startercode/course_materials/exercises
python3 scripts/verify_setup.py
```

You want `Ollama: reachable`. If it is not, start it:

```bash
sudo nohup ollama serve > /tmp/ollama.log 2>&1 &
```

Give it about ten seconds, then run `verify_setup.py` again.

## 2. Run an exercise

```bash
python3 scripts/run_sp.py SP03
```

With no argument, `run_sp.py` lists all twelve.

## 3. Work through it

Each skill pair lives in its own folder:

```
skill-pair-03-aria-indirect-injection/
  EXERCISE.md      read this first
  starter/         the file you edit
  solutions/       check yourself after you have tried
  demo/            the vulnerable and fixed versions from the lesson video
```

You edit exactly one function in `starter/`. The `EXERCISE.md` tells you which one.

## Two exercises need a target service

SP01 and SP02 attack a deliberately vulnerable HTTP endpoint rather than talking to the
model directly. Start it first, in its own terminal:

```bash
cd /voc/startercode/course_materials/target
bash setup_target.sh
./start_target.sh
```

Leave it running and open a second terminal for the exercise.

## If something goes wrong

**The first run is slow or times out.** The model loads into memory on first use. Run
`verify_setup.py` once before starting — it warms the model so you do not pay that cost
inside an exercise.

**The lab times out or a script leaves things in a strange state.** Reload the lab. Your
starter edits and saved reports are kept.

**A script cannot reach the model.** Check `sudo ollama serve` is running, then
`curl http://localhost:11434/api/tags`.
