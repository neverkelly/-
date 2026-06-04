"""
Лабораторная работа №7
Верификация возможности утечки права на модели Take-Grant

Реализует:
- Граф доступов Take-Grant (субъекты, объекты, рёбра с правами)
- Де-юре правила (take, grant, create, remove)
- Де-факто правила (tike, tike*, tike**, grant*, grant**)
- Построение замыкания графа (Девянин: алг. 2.3, 2.4, 2.5)
- Проверку утечки права
"""

from typing import Optional
import copy


# ─────────────────────────────────────────────────────────────
# Базовые структуры
# ─────────────────────────────────────────────────────────────

class Node:
    """Вершина графа: субъект (is_subject=True) или объект."""

    def __init__(self, name: str, is_subject: bool = True):
        self.name = name
        self.is_subject = is_subject

    def __repr__(self):
        kind = "S" if self.is_subject else "O"
        return f"{kind}({self.name})"


class TakeGrantGraph:
    """
    Граф доступов модели Take-Grant.

    nodes  : dict[name -> Node]
    edges  : dict[(src, dst) -> set[rights]]
              rights — произвольные строки, спец. права: 't' и 'g'
    """

    TAKE  = 't'   # право take
    GRANT = 'g'   # право grant

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple[str, str], set[str]] = {}

    # ── вспомогательные ──────────────────────────────────────

    def _ensure(self, name: str) -> Node:
        if name not in self.nodes:
            raise KeyError(f"Вершина «{name}» не найдена в графе")
        return self.nodes[name]

    def _add_edge(self, src: str, dst: str, rights: set[str]) -> None:
        key = (src, dst)
        if key not in self.edges:
            self.edges[key] = set()
        self.edges[key].update(rights)

    def has_right(self, src: str, dst: str, right: str) -> bool:
        return right in self.edges.get((src, dst), set())

    def rights(self, src: str, dst: str) -> set[str]:
        return self.edges.get((src, dst), set()).copy()

    def subjects(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.is_subject]

    def all_nodes(self) -> list[Node]:
        return list(self.nodes.values())

    def copy(self) -> "TakeGrantGraph":
        g = TakeGrantGraph()
        g.nodes = {k: Node(v.name, v.is_subject) for k, v in self.nodes.items()}
        g.edges = {k: v.copy() for k, v in self.edges.items()}
        return g

    # ── добавление вершин вручную ─────────────────────────────

    def add_subject(self, name: str) -> None:
        """Добавить субъект (без применения де-юре правила)."""
        self.nodes[name] = Node(name, is_subject=True)

    def add_object(self, name: str) -> None:
        """Добавить объект."""
        self.nodes[name] = Node(name, is_subject=False)

    def add_rights(self, src: str, dst: str, rights: set[str]) -> None:
        """Добавить права на ребро (оба узла должны существовать)."""
        self._ensure(src)
        self._ensure(dst)
        self._add_edge(src, dst, rights)

    # ── де-юре правила ───────────────────────────────────────

    def rule_take(self, subj_x: str, subj_y: str, obj_z: str,
                  alpha: set[str]) -> bool:
        """
        Правило take (Девянин 2.2):
          Предусловие: x →t y, y →α z
          Результат  : x →α z  добавляется
        """
        x, y, z = subj_x, subj_y, obj_z
        self._ensure(x); self._ensure(y); self._ensure(z)
        if not self.has_right(x, y, self.TAKE):
            print(f"[take] ОТКАЗ: у {x} нет права 't' на {y}")
            return False
        available = self.rights(y, z)
        granted = available & alpha
        if not granted:
            print(f"[take] ОТКАЗ: {y} не имеет прав {alpha} на {z}")
            return False
        self._add_edge(x, z, granted)
        print(f"[take] {x} взял права {granted} с {z} через {y}")
        return True

    def rule_grant(self, subj_x: str, subj_y: str, obj_z: str,
                   alpha: set[str]) -> bool:
        """
        Правило grant (Девянин 2.2):
          Предусловие: x →g y, x →α z
          Результат  : y →α z  добавляется
        """
        x, y, z = subj_x, subj_y, obj_z
        self._ensure(x); self._ensure(y); self._ensure(z)
        if not self.has_right(x, y, self.GRANT):
            print(f"[grant] ОТКАЗ: у {x} нет права 'g' на {y}")
            return False
        available = self.rights(x, z)
        granted = available & alpha
        if not granted:
            print(f"[grant] ОТКАЗ: {x} не имеет прав {alpha} на {z}")
            return False
        self._add_edge(y, z, granted)
        print(f"[grant] {x} передал права {granted} на {z} субъекту {y}")
        return True

    def rule_create(self, subj_x: str, new_name: str,
                    alpha: set[str], is_subject: bool = True) -> bool:
        """
        Правило create (Девянин 2.2):
          Предусловие: x существует как субъект
          Результат  : создаётся новая вершина new_name,
                       добавляется ребро x →α new_name
        """
        self._ensure(subj_x)
        if not self.nodes[subj_x].is_subject:
            print(f"[create] ОТКАЗ: {subj_x} не является субъектом")
            return False
        if new_name in self.nodes:
            print(f"[create] ОТКАЗ: вершина {new_name} уже существует")
            return False
        if is_subject:
            self.add_subject(new_name)
        else:
            self.add_object(new_name)
        self._add_edge(subj_x, new_name, alpha)
        kind = "субъект" if is_subject else "объект"
        print(f"[create] {subj_x} создал {kind} {new_name} с правами {alpha}")
        return True

    def rule_remove(self, subj_x: str, obj_y: str,
                    alpha: set[str]) -> bool:
        """
        Правило remove (Девянин 2.2):
          Предусловие: x →α y  (α ⊆ rights(x,y))
          Результат  : права α удаляются с ребра x → y
        """
        self._ensure(subj_x); self._ensure(obj_y)
        current = self.rights(subj_x, obj_y)
        removable = current & alpha
        if not removable:
            print(f"[remove] ОТКАЗ: {subj_x} не владеет правами {alpha} на {obj_y}")
            return False
        self.edges[(subj_x, obj_y)] -= removable
        if not self.edges[(subj_x, obj_y)]:
            del self.edges[(subj_x, obj_y)]
        print(f"[remove] У {subj_x} удалены права {removable} на {obj_y}")
        return True

    # ── отображение графа ─────────────────────────────────────

    def print_graph(self, title: str = "Граф доступов") -> None:
        print(f"\n{'═'*55}")
        print(f"  {title}")
        print(f"{'═'*55}")
        print("Вершины:")
        for n in self.nodes.values():
            kind = "Субъект" if n.is_subject else "Объект "
            print(f"  [{kind}] {n.name}")
        print("\nРёбра (src → dst : права):")
        if not self.edges:
            print("  (рёбра отсутствуют)")
        for (src, dst), rts in sorted(self.edges.items()):
            print(f"  {src} → {dst} : {{{', '.join(sorted(rts))}}}")
        print(f"{'─'*55}\n")


# ─────────────────────────────────────────────────────────────
# Алгоритмы замыкания (Девянин, §2.5)
# ─────────────────────────────────────────────────────────────

def build_tg_closure(g: TakeGrantGraph,
                     verbose: bool = True) -> TakeGrantGraph:
    """
    Алгоритм 2.3 (Девянин) — замыкание графа Take-Grant.

    Применяет правила take и grant до стабилизации, строит
    граф G*, содержащий все достижимые де-юре права.
    Возвращает новый граф (исходный не изменяется).
    """
    if verbose:
        print("\n" + "="*55)
        print("  АЛГОРИТМ 2.3 — Замыкание графа (G*)")
        print("="*55)

    gc = g.copy()
    step = 0
    changed = True
    while changed:
        changed = False
        step += 1
        edges_snap = list(gc.edges.items())

        for (x, y), rxy in edges_snap:
            if not gc.nodes[x].is_subject:
                continue

            # take: x →t y, y →α z  =>  x →α z
            if TakeGrantGraph.TAKE in rxy:
                for (y2, z), ryz in list(gc.edges.items()):
                    if y2 != y:
                        continue
                    before = gc.rights(x, z)
                    gc._add_edge(x, z, ryz)
                    after = gc.rights(x, z)
                    if after != before:
                        changed = True
                        if verbose:
                            new_r = after - before
                            print(f"  [take]  {x} получает {new_r} на {z} "
                                  f"(через {y})")

            # grant: x →g y, x →α z  =>  y →α z
            if TakeGrantGraph.GRANT in rxy:
                for (x2, z), rxz in list(gc.edges.items()):
                    if x2 != x:
                        continue
                    before = gc.rights(y, z)
                    gc._add_edge(y, z, rxz)
                    after = gc.rights(y, z)
                    if after != before:
                        changed = True
                        if verbose:
                            new_r = after - before
                            print(f"  [grant] {x} передаёт {new_r} на {z} "
                                  f"субъекту {y}")

    if verbose:
        print(f"\nЗамыкание построено за {step} итераций.")
    return gc


# ─────────────────────────────────────────────────────────────
# Де-факто правила и граф информационных потоков
# ─────────────────────────────────────────────────────────────

def can_share(right: str,
              source: str,
              target: str,
              g: TakeGrantGraph,
              verbose: bool = True) -> bool:

    if verbose:
        print("\n" + "="*55)
        print(f"  АЛГОРИТМ can_share('{right}', {source}, {target})")
        print("="*55)

    g._ensure(source); g._ensure(target)
    gc = build_tg_closure(g, verbose=verbose)

    # Шаг 0: прямое право в замыкании
    if gc.has_right(source, target, right):
        if verbose:
            print(f"\n✓ {source} УЖЕ имеет право '{right}' на {target} "
                  f"в замыкании G*.")
        return True

    # Шаг 1: множество субъектов, которые имеют право α на target в G*
    holders: set[str] = set()
    for (s, d), rts in gc.edges.items():
        if d == target and right in rts and gc.nodes[s].is_subject:
            holders.add(s)
    if verbose:
        print(f"\nВладельцы права '{right}' на {target} в G*: "
              f"{holders or '∅'}")

    if not holders:
        if verbose:
            print(f"✗ Никто в G* не имеет права '{right}' на {target}. "
                  f"Утечка невозможна.")
        return False

    # Шаг 2: достижимые через 'tg'-цепочку субъекты от source
    # Субъект b достижим из a, если существует путь a→…→b,
    # где каждое ребро содержит 't' или 'g' (в G*).
    reachable = _tg_reachable(source, gc)
    if verbose:
        print(f"Субъекты, достижимые из {source} по 'tg'-рёбрам в G*: "
              f"{reachable}")

    # Шаг 3: пересечение
    bridge = holders & reachable
    if bridge:
        if verbose:
            print(f"\n✓ Найден мост через субъектов: {bridge}")
            print(f"  => {source} МОЖЕТ получить право '{right}' на {target}.")
        return True
    else:
        if verbose:
            print(f"\n✗ Мост не найден.")
            print(f"  => {source} НЕ может получить право '{right}' на {target}.")
        return False


def _tg_reachable(start: str, g: TakeGrantGraph) -> set[str]:
    """BFS/DFS по 'tg'-рёбрам от start среди субъектов."""
    visited: set[str] = {start}
    queue = [start]
    while queue:
        cur = queue.pop()
        for (s, d), rts in g.edges.items():
            if s == cur and (TakeGrantGraph.TAKE in rts or
                             TakeGrantGraph.GRANT in rts):
                if d in g.nodes and g.nodes[d].is_subject and d not in visited:
                    visited.add(d)
                    queue.append(d)
    return visited


# ─────────────────────────────────────────────────────────────
# Граф информационных потоков (алг. 2.5 Девянин)
# ─────────────────────────────────────────────────────────────

def build_info_flow_graph(g: TakeGrantGraph,
                          verbose: bool = True) -> dict[str, set[str]]:

    if verbose:
        print("\n" + "="*55)
        print("  АЛГОРИТМ 2.5 — Граф информационных потоков")
        print("="*55)

    gc = build_tg_closure(g, verbose=False)
    subjs = [n.name for n in gc.subjects()]

    # Для каждого субъекта — множество объектов с доступом в G*
    access: dict[str, set[str]] = {s: set() for s in subjs}
    for (s, d), rts in gc.edges.items():
        if gc.nodes[s].is_subject and rts:
            access[s].add(d)

    # Граф потоков: flow[a] = множество субъектов, к которым
    # может потечь информация от a
    flow: dict[str, set[str]] = {s: set() for s in subjs}
    for a in subjs:
        for b in subjs:
            if a == b:
                continue
            # общие объекты с доступом
            shared = access[a] & access[b]
            if shared:
                flow[a].add(b)
                if verbose:
                    print(f"  Поток {a} → {b}  (общие объекты: {shared})")

    if verbose:
        if not any(flow.values()):
            print("  (информационных потоков не обнаружено)")
    return flow



# Демонстрационный сценарий


def demo():
    print("\n" + "█"*55)
    print("  Лабораторная работа №7  |  Модель Take-Grant")
    print("█"*55)

    # ── 1. Формируем начальный граф ───────────────────────────
    print("\n─── 1. Создание исходного графа ───────────────────────")
    g = TakeGrantGraph()

    # Субъекты
    g.add_subject("Alice")
    g.add_subject("Bob")
    g.add_subject("Charlie")

    # Объекты
    g.add_object("File1")
    g.add_object("File2")
    g.add_object("DB")

    # Начальные права
    #  Alice →{t,g,r,w} File1  (Alice владеет File1)
    #  Alice →{g}        Bob   (Alice может делегировать Bob)
    #  Bob   →{r,w}      File2 (Bob работает с File2)
    #  Bob   →{t}        Charlie (Bob может делегировать take Charlie)
    #  Charlie →{r}      DB   (Charlie читает DB)
    g.add_rights("Alice",   "File1",   {'t', 'g', 'r', 'w'})
    g.add_rights("Alice",   "Bob",     {'g'})
    g.add_rights("Bob",     "File2",   {'r', 'w'})
    g.add_rights("Bob",     "Charlie", {'t'})
    g.add_rights("Charlie", "DB",      {'r'})

    g.print_graph("Исходный граф G")

    # ── 2. Демонстрация де-юре правил ────────────────────────
    print("─── 2. Применение де-юре правил ───────────────────────")

    # create: Alice создаёт новый объект SecretFile
    g.rule_create("Alice", "SecretFile", {'r', 'w', 't', 'g'}, is_subject=False)

    # grant: Alice передаёт право 'r' на File1 субъекту Bob
    g.rule_grant("Alice", "Bob", "File1", {'r'})

    # take: Bob берёт право 'r' на File1 (через Charlie? — нет прав)
    #       покажем неудачный take для демонстрации
    g.rule_take("Bob", "Charlie", "DB", {'r'})      # успешно
    g.rule_take("Bob", "Alice",  "File1", {'w'})    # неудача (нет t→Alice)

    # remove: Charlie теряет право 'r' на DB
    g.rule_remove("Charlie", "DB", {'r'})

    # create субъекта: Bob создаёт нового субъекта Dave
    g.rule_create("Bob", "Dave", {'t', 'g', 'r'}, is_subject=True)

    g.print_graph("Граф G после де-юре операций")

    # Восстановим Charlie→DB для интересного замыкания
    g.add_rights("Charlie", "DB", {'r'})
    g.add_rights("Dave",    "File2", {'r', 'w'})
    g.add_rights("Bob",     "Dave",  {'g'})

    g.print_graph("Граф G (после дополнительных рёбер)")

    # ── 3. Замыкание G* (алг. 2.3) ───────────────────────────
    print("─── 3. Построение замыкания G* (алг. 2.3) ─────────────")
    gc = build_tg_closure(g, verbose=True)
    gc.print_graph("Замыкание G*")

    # ── 4. Проверка can_share (алг. 2.4) ─────────────────────
    print("─── 4. Проверка can_share (алг. 2.4 / 2.5) ────────────")

    scenarios = [
        ("Alice", "DB",      "r"),
        ("Dave",  "File1",   "r"),
        ("Bob",   "SecretFile", "w"),
        ("Charlie","File1",  "r"),
    ]

    results = []
    for src, dst, right in scenarios:
        result = can_share(right, src, dst, g, verbose=True)
        results.append((src, dst, right, result))

    # ── 5. Граф информационных потоков (алг. 2.5) ─────────────
    print("─── 5. Граф информационных потоков (алг. 2.5) ─────────")
    flow = build_info_flow_graph(g, verbose=True)

    # ── 6. Итоговая таблица ───────────────────────────────────
    print("\n" + "="*55)
    print("  ИТОГОВАЯ ТАБЛИЦА: can_share")
    print("="*55)
    print(f"  {'Субъект':<12} {'Право':<6} {'Объект':<12} {'Результат'}")
    print(f"  {'─'*12} {'─'*6} {'─'*12} {'─'*10}")
    for src, dst, right, result in results:
        verdict = "✓ ВОЗМОЖНА" if result else "✗ НЕВОЗМОЖНА"
        print(f"  {src:<12} '{right}'   {dst:<12} {verdict}")

    print("\n" + "="*55)
    print("  ГРАФ ИНФОРМАЦИОННЫХ ПОТОКОВ")
    print("="*55)
    for src, dsts in flow.items():
        if dsts:
            print(f"  {src}  →  {', '.join(sorted(dsts))}")
    if not any(flow.values()):
        print("  (потоки отсутствуют)")

    print("\n" + "█"*55)
    print("  Работа завершена.")
    print("█"*55 + "\n")


if __name__ == "__main__":
    demo()
