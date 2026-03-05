import pygame
import sys
import random
from collections import defaultdict
from copy import deepcopy

#конфиг

WIDTH = 1200
HEIGHT = 800
TOP_PANEL = 140
CELL_SIZE = 8

BG_COLOR = (15, 15, 15)
GRID_COLOR = (40, 40, 40)
ALIVE_COLOR = (0, 255, 255)
TEXT_COLOR = (220, 220, 220)

BUTTON_COLOR = (70, 70, 70)
BUTTON_ACTIVE = (0, 140, 200)

pygame.init()
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Game of Life")
font = pygame.font.SysFont("arial", 16)
clock = pygame.time.Clock()

#паттерны

PATTERNS = {
    "GLIDER": [(1,0),(2,1),(0,2),(1,2),(2,2)],
    "BLINKER": [(0,1),(1,1),(2,1)],
    "BLOCK": [(0,0),(0,1),(1,0),(1,1)],
    "TOAD": [(1,0),(2,0),(3,0),(0,1),(1,1),(2,1)],
    "BEACON": [(0,0),(1,0),(0,1),(3,2),(2,3),(3,3)],
    "LWSS": [(1,0),(4,0),(0,1),(0,2),(4,2),(0,3),(1,3),(2,3),(3,3)]
}

#правиланазв

RULES = {
    "Life (B3/S23)": "B3/S23",
    "HighLife (B36/S23)": "B36/S23",
    "Day&Night (B3678/S34678)": "B3678/S34678",
    "Seeds (B2/S)": "B2/S",
    "Life w/o Death (B3/S012345678)": "B3/S012345678"
}

#игра

class GameOfLife:
    def __init__(self, rule="B3/S23"):
        self.live = set()
        self.history = []
        self.set_rule(rule)
        self.torus = False

    def set_rule(self, rule):
        self.birth = set()
        self.survive = set()
        for part in rule.split("/"):
            if part.startswith("B"):
                self.birth = set(map(int, part[1:])) if part[1:] else set()
            if part.startswith("S"):
                self.survive = set(map(int, part[1:])) if part[1:] else set()

    def step(self, w, h):
        self.history.append(deepcopy(self.live))
        counts = defaultdict(int)

        for (x, y) in self.live:
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    if dx == 0 and dy == 0:
                        continue
                    nx, ny = x + dx, y + dy
                    if self.torus:
                        nx %= w
                        ny %= h
                    counts[(nx, ny)] += 1

        new_live = set()
        for cell, c in counts.items():
            if cell in self.live:
                if c in self.survive:
                    new_live.add(cell)
            else:
                if c in self.birth:
                    new_live.add(cell)

        self.live = new_live

    def step_back(self):
        if self.history:
            self.live = self.history.pop()

    def clear(self):
        self.live.clear()
        self.history.clear()

    def stamp_pattern(self, pattern, x, y):
        for dx, dy in PATTERNS[pattern]:
            self.live.add((x + dx, y + dy))

#интерфейс

class Button:
    def __init__(self, x, y, w, h, text, toggle=False):
        self.rect = pygame.Rect(x, y, w, h)
        self.text = text
        self.toggle = toggle
        self.active = False
        self.action = None

    def draw(self):
        color = BUTTON_ACTIVE if self.active else BUTTON_COLOR
        pygame.draw.rect(screen, color, self.rect)
        label = font.render(self.text, True, TEXT_COLOR)
        screen.blit(label, (self.rect.x + 8, self.rect.y + 7))

    def handle(self, pos):
        if self.rect.collidepoint(pos):
            if self.toggle:
                self.active = not self.active
            if self.action:
                self.action()

class Slider:
    def __init__(self, x, y, w, min_val, max_val, start):
        self.rect = pygame.Rect(x, y, w, 5)
        self.min = min_val
        self.max = max_val
        self.val = start
        self.knob = pygame.Rect(x, y - 5, 10, 15)
        self.drag = False

    def draw(self):
        pygame.draw.rect(screen, (120,120,120), self.rect)
        pos = self.rect.x + (self.val - self.min)/(self.max-self.min)*self.rect.w
        self.knob.x = int(pos)
        pygame.draw.rect(screen, (200,200,200), self.knob)
        txt = font.render(f"Speed: {self.val}", True, TEXT_COLOR)
        screen.blit(txt, (self.rect.x, self.rect.y - 25))

    def handle(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            pos = event.pos
            if self.knob.collidepoint(event.pos):
                self.drag = True
        if event.type == pygame.MOUSEBUTTONUP:
            self.drag = False
        if event.type == pygame.MOUSEMOTION and self.drag:
            x = max(self.rect.x, min(event.pos[0], self.rect.x+self.rect.w))
            ratio = (x-self.rect.x)/self.rect.w
            self.val = int(self.min + ratio*(self.max-self.min))


cols = WIDTH // CELL_SIZE
rows = (HEIGHT - TOP_PANEL) // CELL_SIZE

#камера
offset_x = 0
offset_y = 0
zoom = 1

game = GameOfLife()
running = False
generation = 0
selected_pattern = "GLIDER"
stamp_mode = False

pause_btn = Button(10, 10, 80, 30, "Pause", toggle=True)
torus_btn = Button(100, 10, 80, 30, "Torus", toggle=True)
step_btn = Button(190, 10, 80, 30, "Step")
reset_btn = Button(280, 10, 80, 30, "Reset")
random_btn = Button(370, 10, 90, 30, "Random")
back_btn = Button(470, 10, 90, 30, "StepBack")
stamp_btn = Button(570, 10, 90, 30, "Stamp", toggle=True)

buttons = [pause_btn, torus_btn, step_btn, reset_btn,
           random_btn, back_btn, stamp_btn]

speed_slider = Slider(10, 110, 200, 1, 60, 10)

pause_btn.action = lambda: globals().update(running=pause_btn.active)
torus_btn.action = lambda: setattr(game, "torus", torus_btn.active)
step_btn.action = lambda: game.step(cols, rows)
reset_btn.action = lambda: game.clear()
random_btn.action = lambda: game.live.update(
    {(random.randint(0, cols-1), random.randint(0, rows-1)) for _ in range(600)}
)
back_btn.action = lambda: game.step_back()
stamp_btn.action = lambda: globals().update(stamp_mode=stamp_btn.active)

#кнопки правил

rule_buttons = []
rx = 10
ry = 50

for name in RULES:
    btn = Button(rx, ry, 210, 30, name)
    rule_buttons.append(btn)
    rx += 220

current_rule = list(RULES.keys())[0]

def make_rule_action(rule_name):
    def action():
        global current_rule
        current_rule = rule_name
        game.set_rule(RULES[rule_name])
        game.clear()
        for b in rule_buttons:
            b.active = (b.text == rule_name)
    return action

for b in rule_buttons:
    b.action = make_rule_action(b.text)

rule_buttons[0].active = True

#луп

while True:
    screen.fill(BG_COLOR)

    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            pygame.quit()
            sys.exit()

        speed_slider.handle(event)

        #зум
        if event.type == pygame.MOUSEWHEEL:
            if event.y > 0:
                zoom *= 1.1
            if event.y < 0:
                zoom /= 1.1
            zoom = max(0.2, min(zoom, 5))

        if event.type == pygame.MOUSEBUTTONDOWN:
            pos = event.pos
            for b in buttons:
                b.handle(pos)
            for b in rule_buttons:
                b.handle(pos)

            if pos[1] > TOP_PANEL:
                gx = int(pos[0] / (CELL_SIZE * zoom) + offset_x)
                gy = int((pos[1] - TOP_PANEL) / (CELL_SIZE * zoom) + offset_y)

                if stamp_mode:
                    game.stamp_pattern(selected_pattern, gx, gy)
                else:
                    game.live.add((gx, gy))

        if event.type == pygame.KEYDOWN:
            #камера
            if event.key == pygame.K_w:
                offset_y -= 5
            if event.key == pygame.K_s:
                offset_y += 5
            if event.key == pygame.K_a:
                offset_x -= 5
            if event.key == pygame.K_d:
                offset_x += 5
            if event.key == pygame.K_RIGHT:
                patterns_list = list(PATTERNS.keys())
                idx = patterns_list.index(selected_pattern)
                selected_pattern = patterns_list[(idx+1)%len(patterns_list)]
            if event.key == pygame.K_LEFT:
                patterns_list = list(PATTERNS.keys())
                idx = patterns_list.index(selected_pattern)
                selected_pattern = patterns_list[(idx-1)%len(patterns_list)]

    if running:
        game.step(cols, rows)
        generation += 1

    #сетка
    for x in range(cols):
        pygame.draw.line(screen, GRID_COLOR,
                         (x*CELL_SIZE, TOP_PANEL),
                         (x*CELL_SIZE, HEIGHT))
    for y in range(rows):
        pygame.draw.line(screen, GRID_COLOR,
                         (0, y*CELL_SIZE+TOP_PANEL),
                         (WIDTH, y*CELL_SIZE+TOP_PANEL))

    #клетки
    for (x, y) in game.live:
        screen_x = (x - offset_x) * CELL_SIZE * zoom
        screen_y = (y - offset_y) * CELL_SIZE * zoom + TOP_PANEL

        pygame.draw.rect(
            screen,
            ALIVE_COLOR,
            (screen_x,
             screen_y,
             CELL_SIZE * zoom,
             CELL_SIZE * zoom)
        )

    #интерфейс
    for b in buttons:
        b.draw()

    for b in rule_buttons:
        b.draw()

    speed_slider.draw()

    pattern_text = font.render(f"Pattern: {selected_pattern} (← →)",
                               True, TEXT_COLOR)
    screen.blit(pattern_text, (400, 110))

    info = font.render(f"Cells: {len(game.live)}  Gen: {generation}",
                       True, TEXT_COLOR)
    screen.blit(info, (800, 110))


    pygame.display.flip()
    clock.tick(speed_slider.val)