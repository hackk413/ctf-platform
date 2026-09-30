"""
CTF Atlas — Steganography Chapters
"""

chapters = {}

chapters["stego-deep"] = {
    "id": "stego-deep",
    "domain": "stego",
    "category": "Steganography & Data Hiding",
    "title": "Pixel Plane Bit Manipulation, Slack Space Carving & Audio Spectrograms",
    "subtitle": "Least Significant Bit (LSB) Extraction, PNG IEND Chunk Appendices, Steghide Discrete Cosine Transforms & Spectrograms",
    "diagram": """+-------------------------------------------------------------+
|                      PNG File Byte Structure                |
+-------------------------------------------------------------+
Offset 0x0000: 89 50 4E 47 0D 0A 1A 0A  (8-byte PNG Magic Signature)
Offset 0x000C: IHDR Chunk (Width, Height, Bit Depth, Color Type)
Offset 0x0021: IDAT Chunks (Zlib-compressed deflate image raster data)
Offset 0x0FA0: IEND Chunk (49 45 4E 44 AE 42 60 82)
+-------------------------------------------------------------+
               |
               v
SLACK SPACE / APPENDED PAYLOAD (Ignored by standard image viewers!):
Offset 0x0FA8: 50 4B 03 04 ... (Embedded ZIP Archive containing flag.txt!)
-> Detect via: binwalk -B image.png OR strings -n 8 image.png
-> Carve via: dd if=image.png of=extracted.zip bs=1 skip=4008""",
    "theory": """Steganography (from Greek steganos 'hidden' and graphein 'writing') is the practice of concealing a secret message, file, or image within another ordinary, non-secret carrier medium (such as an image, audio file, video, or text) without altering the outward appearance of the carrier. Unlike cryptography, which protects the confidentiality of message content, steganography conceals the very existence of the communication.

Steganographic Carrier Domains & Techniques:
1. File Structure Slack Space (Format Appendices):
   Many structured file formats possess explicit end-of-file delimiters. For example, Portable Network Graphics (PNG, RFC 2083) terminates with an `IEND` chunk (hex `49 45 4E 44 AE 42 60 82`), while JPEG terminates with an End of Image (EOI) marker `0xFF 0xD9`. Standard graphical renderers (browsers, image viewers) stop parsing once the terminal chunk is encountered and silently ignore any subsequent bytes. Attackers append arbitrary archives, encrypted payloads, or plaintext flags after the terminator.
2. Spatial Domain Least Significant Bit (LSB) Encoding:
   In uncompressed or lossless 24-bit RGB images (BMP, PNG), each pixel is represented by three bytes (Red, Green, Blue) ranging from 0 to 255. Altering the least significant bit (bit 0) of a color byte alters the color intensity by at most 1/255 ($< 0.4\\%$)—a delta completely imperceptible to human visual perception. By replacing the LSB of consecutive color bytes with the bits of a secret payload, an attacker embeds data at an encoding density of 3 bits per pixel (or 1 bit per byte).
3. Transform / Frequency Domain (Steghide & JPEG DCT):
   JPEG utilizes Discrete Cosine Transform (DCT) lossy compression. Tools like `steghide` embed secret data by modulating the least significant bits of the quantized DCT frequency coefficients rather than raw spatial pixels. Steghide encrypts payloads using AES/Blowfish and pseudo-randomly scatters bits across frequency bins using a user-supplied passphrase.
4. Audio Spectrograms:
   In audio steganography (WAV, MP3, FLAC), secret text or images can be hidden within the audio frequency spectrum. Solvers analyze the audio using a Fast Fourier Transform (FFT) spectrogram viewer (Sonic Visualiser, Audacity) to visually reveal text written into high-frequency audio bands.""",
    "commands": [
        {
            "cmd": "zsteg -a image.png",
            "why": "Automates detection of LSB steganography across all color planes (RGB, BGR, RGBA), bit depths (1-8), and channel orders.",
            "when": "First automated command when triaging PNG or BMP steganography challenges.",
            "internals": "Extracts bit slices from raw pixel scanlines and matches against magic byte signatures.",
            "pitfalls": "zsteg only supports PNG and BMP formats; does not work on lossy JPEG images."
        },
        {
            "cmd": "binwalk -e image.png",
            "why": "Scans for embedded or appended file signatures (ZIP, TAR, 7Z, ELF) and automatically extracts them.",
            "when": "Checking for polyglot files or slack-space archive append attacks.",
            "internals": "Matches byte patterns against libmagic signature tables and extracts slices to disk.",
            "pitfalls": "Can produce false-positive zlib extractions on legitimate PNG IDAT chunks."
        },
        {
            "cmd": "steghide extract -sf picture.jpg -p 'password'",
            "why": "Extracts hidden encrypted data from JPEG or WAV files embedded using Steghide.",
            "when": "When metadata or hints suggest a passphrase-protected DCT stego carrier.",
            "internals": "Recovers pseudo-random graph of DCT coefficients and decrypts payload.",
            "pitfalls": "If password is unknown, brute-force with `stegseek picture.jpg rockyou.txt`."
        },
        {
            "cmd": "stegseek picture.jpg /usr/share/wordlists/rockyou.txt",
            "why": "Lightning-fast steghide cracker capable of testing millions of passwords per second.",
            "when": "Cracking password-protected steghide carriers.",
            "internals": "Bypasses slow C library calls and tests DCT graph hashes directly in memory.",
            "pitfalls": "Only works on Steghide implementations."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "CLI: `zsteg -a stego.png | grep -iE 'flag|CTF'` -> extracts hidden LSB string in 1 second.",
        "gui_workflow": "Aperi'Solve (aperisolve.com) / StegSolve: Visual bit-plane browser (Red 0, Green 0, Blue 0, alpha planes, inversion, stereogram solver). Sonic Visualiser for audio spectrograms.",
        "speed_tip": "Run `stegseek file.jpg rockyou.txt` first on JPEGs; it cracks 90% of CTF steghide challenges in under 2 seconds."
    },
    "triage_workflow": [
        "1. Check File Format: Is it PNG (lossless), JPEG (lossy), BMP, WAV, or MP3?",
        "2. Inspect File Structure: Run `pngcheck -v image.png` or `binwalk image.png` to detect trailing bytes after IEND.",
        "3. String Triage: Run `strings image.png | tail -n 20` to spot plaintext append attacks.",
        "4. LSB Analysis: For PNG/BMP, run `zsteg -a image.png` or browse bit planes in StegSolve.",
        "5. Steghide Check: For JPEG/WAV, run `stegseek image.jpg rockyou.txt`.",
        "6. Audio Analysis: Open audio files in Sonic Visualiser and add a Spectrogram layer (Layer -> Add Spectrogram)."
    ],
    "writeup": {
        "ctf_event": "PicoCTF / National Cyber League",
        "challenge_name": "Matryoshka-Image (Nested Polyglot Stego)",
        "scenario": "Solvers are given 'challenge.png'. Opening it displays an image of a Russian nesting doll. Solvers must find the hidden flag.",
        "solve_steps": [
            "1. Run binwalk: `binwalk challenge.png`.",
            "2. Notice appended ZIP archive starting at offset 0x4A210 after the PNG IEND marker.",
            "3. Extract archive: `binwalk -e challenge.png` -> creates directory `_challenge.png.extracted/`.",
            "4. Extracted directory contains: `doll2.png`.",
            "5. Repeat process on `doll2.png`: contains another embedded archive with `doll3.png`.",
            "6. Inspect `doll3.png` with zsteg: `zsteg -a doll3.png`.",
            "7. zsteg detects text in `b1,r,lsb,xy`: `CTF{M4TRY0SHK4_ST3G0_P0LYGL0T_2026}`.",
            "8. Flag: CTF{M4TRY0SHK4_ST3G0_P0LYGL0T_2026}"
        ],
        "exploit_code": """#!/usr/bin/env python3
import subprocess

def solve_stego():
    print("[*] Extracting nested layers via binwalk...")
    subprocess.run("binwalk -e --matryoshka challenge.png", shell=True)
    print("[*] Running zsteg on deepest image...")
    flag = subprocess.check_output("zsteg -a extracted_doll.png | grep 'CTF{'", shell=True, text=True)
    print("[+] Flag:", flag.strip())

if __name__ == '__main__':
    solve_stego()""",
        "flag": "CTF{M4TRY0SHK4_ST3G0_P0LYGL0T_2026}",
        "mitigation": "Strip unneeded metadata and trailing slack space from user-uploaded images using imaging pipelines (e.g. `exiftool -all= -overwrite_original` or re-encoding through ImageMagick `convert in.png out.png`)."
    }
}
