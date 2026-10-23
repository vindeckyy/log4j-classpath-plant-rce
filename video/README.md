# POC video

`video/build.py` renders the proof-of-concept video for this finding:
`video/out/log4j-classpath-plant-poc.mp4` (1920×1080, 30 fps, H.264 + AAC, burned-in captions).
`video/out/log4j-classpath-plant-poc.srt` is the same narration as a subtitle file.

The footage in the video is **not** mocked up: every terminal scene captures the real output of
`lab/` at build time, so the video shows exactly what the proof of concept prints.

## Regenerate

```bash
python3 -m venv ~/.venvs/piper
~/.venvs/piper/bin/pip install piper-tts
mkdir -p ~/.local/share/piper-voices
curl -sL -o ~/.local/share/piper-voices/en_US-lessac-medium.onnx \
  https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US/lessac/medium/en_US-lessac-medium.onnx
curl -sL -o ~/.local/share/piper-voices/en_US-lessac-medium.onnx.json \
  https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US/lessac/medium/en_US-lessac-medium.onnx.json
sudo apt-get install -y ffmpeg fonts-inter fonts-jetbrains-mono

python3 video/build.py            # full video + srt
python3 video/build.py --scene demo-rce --preview   # one scene -> PNG frames
```

`video/script.py` holds the content: the narration and the visual spec of every scene.
Narration is synthesised per sentence, so the burned-in captions and the `.srt` timings are exact.

## What the video covers

1. **Background** — what Log4j is, what the classpath is, in plain language.
2. **The mechanism** — the two fixed-name classpath resources, the planted
   `log4j2.system.properties`, the attacker's `pwn.xml`.
3. **Proof of concept** — the victim application, the negative control, the order of events.
4. **Blast radius** — `log4j-api` alone, the supply-chain jar, outbound traffic redirection.
5. **Why it matters** — comparison with Log4Shell, reach, CVSS, remediation, detection.
6. **Disclosure** — first disclosure, where the report goes, where the material lives.

Every command in the video runs `lab/` on localhost only; nothing leaves the machine.
