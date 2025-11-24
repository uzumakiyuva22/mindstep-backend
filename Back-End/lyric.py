import time
import sys

verse1 = [
    ("Vaazhum naal ellam 🎵", 0.3),   
    ("Nee kaanum thooraththil ✨", 0.5), 
    ("Vazhvene naan vazhvene... ❤️", 1), 
    ("Kaatril poo pookum 🌸", 0.5),
    ("Un vaasam naan vaangi 💫", 0.5),
    ("Serpene,Naan serpene... 🌟", 1),
    ("Veedil un pinne 🏡", 0.5),
    ("Vazhattum oor mounam 🌙", 0.3),
    ("Aavene naan aavene... 🌟", 2),
    ("Neeye nee endru 💖", 0.8),
    ("Oor vazhkai naan vazhnthu 🌈", 1),
    ("Povene naan povene... 🎵", 0.5)
]

def type_line(line, speed=0.1):
    """Simulate slow typing effect for a single line"""
    for char in line:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

def sing_lyrics(lines):
    for line, delay in lines:
        type_line(line, speed=0.1)
        time.sleep(delay)

print("🎶 Song : Sidu Sidu 🎶\n")
time.sleep(1)
sing_lyrics(verse1)
print("\n Dedicated To My Friend D ☺️")
print("\n I Waiting For Your Call and I Miss You every Day 💙")
