"""Reproduce the original Dyad mark with Pillow; no network or generated imagery."""

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1] / "assets"
ROOT.mkdir(exist_ok=True)
SCALE = 4
BACKGROUND = "#151c1f"
MINT = "#68e0b7"
image = Image.new("RGBA", (256 * SCALE, 256 * SCALE))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((8*SCALE, 8*SCALE, 248*SCALE, 248*SCALE), radius=54*SCALE, fill=BACKGROUND)

def curve(start, control1, control2, end):
    return [tuple((1-t)**3*start[j]+3*(1-t)**2*t*control1[j]+3*(1-t)*t*t*control2[j]+t**3*end[j] for j in range(2)) for i in range(1,65) for t in [i/64]]

# A quiet, split D: an independent stem and open bowl, two complementary parts.
points = [(112,64),(126,64)]
points += curve((126,64),(171,64),(192,101),(192,128))
points += curve((192,128),(192,155),(171,192),(126,192))
points += [(112,192),(112,168),(126,168)]
points += curve((126,168),(148,168),(168,150),(168,128))
points += curve((168,128),(168,106),(148,88),(126,88))
points += [(112,88)]
draw.polygon([(round(x*SCALE),round(y*SCALE)) for x,y in points],fill=MINT)
draw.rounded_rectangle((64*SCALE,64*SCALE,88*SCALE,192*SCALE),radius=12*SCALE,fill=MINT)
image = image.resize((512,512),Image.Resampling.LANCZOS)
image.save(ROOT / "dyad.png")
image.save(ROOT / "dyad.ico", sizes=[(size,size) for size in (16,24,32,48,64,128,256)])
(ROOT / "dyad.svg").write_text('''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <rect x="8" y="8" width="240" height="240" rx="54" fill="#151c1f"/>
  <g fill="#68e0b7">
    <rect x="64" y="64" width="24" height="128" rx="12"/>
    <path d="M112 64h14c45 0 66 37 66 64s-21 64-66 64h-14v-24h14c22 0 42-18 42-40s-20-40-42-40h-14Z"/>
  </g>
</svg>
''',encoding="utf-8")
