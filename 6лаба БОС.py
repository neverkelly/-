"""
Лабораторная работа №6 — Модель Харрисона–Руззо–Ульмана (HRU)
==============================================================
Права:
  O — владение (own)
  R — чтение  (read)
  W — запись  (write)

Команды:
  1. create_subject <s>
  2. delete_subject <s>
  3. create_object <o> <owner>
  4. delete_object <o> <who>          — требует O у who
  5. grant <right> <o> <s1> <s2>     — s1 (владелец O) передаёт right на o субъекту s2
  6. revoke <right> <o> <s1> <s2>    — s1 (владелец O) забирает right на o у s2
  7. show subject <s>
  8. show object <o>
  9. help
  10. exit
"""

from __future__ import annotations
from typing import Dict, Set

RIGHTS = {"O", "R", "W"}
RIGHTS_FULL = {"O": "Владение", "R": "Чтение", "W": "Запись"}


class HRUModel:
    """Матрица доступа модели HRU."""

    def __init__(self) -> None:
        self.subjects: list[str] = []
        self.objects: list[str] = []
        # acm[subject][object] = set of rights
        self.acm: Dict[str, Dict[str, Set[str]]] = {}

    # ------------------------------------------------------------------ #
    #  Вспомогательные методы                                              #
    # ------------------------------------------------------------------ #

    def _get_cell(self, subject: str, obj: str) -> Set[str]:
        self.acm.setdefault(subject, {}).setdefault(obj, set())
        return self.acm[subject][obj]

    def has_right(self, subject: str, obj: str, right: str) -> bool:
        return right in self.acm.get(subject, {}).get(obj, set())

    def _add_right(self, subject: str, obj: str, right: str) -> None:
        self._get_cell(subject, obj).add(right)

    def _remove_right(self, subject: str, obj: str, right: str) -> None:
        cell = self.acm.get(subject, {}).get(obj)
        if cell:
            cell.discard(right)

    # ------------------------------------------------------------------ #
    #  Команды                                                             #
    # ------------------------------------------------------------------ #

    def create_subject(self, s: str) -> None:
        """Команда: создать субъект s."""
        if s in self.subjects:
            raise ValueError(f"Субъект '{s}' уже существует.")
        self.subjects.append(s)
        print(f"[OK] Субъект '{s}' создан.")

    def delete_subject(self, s: str) -> None:
        """Команда: удалить субъект s (и его строку из матрицы)."""
        if s not in self.subjects:
            raise ValueError(f"Субъект '{s}' не найден.")
        self.subjects.remove(s)
        self.acm.pop(s, None)
        print(f"[OK] Субъект '{s}' удалён (его права в матрице очищены).")

    def create_object(self, o: str, owner: str) -> None:
        """Команда: создать объект o субъектом owner.
        Владелец получает права O, R, W на созданный объект.
        """
        if owner not in self.subjects:
            raise ValueError(f"Субъект-владелец '{owner}' не найден.")
        if o in self.objects:
            raise ValueError(f"Объект '{o}' уже существует.")
        self.objects.append(o)
        for right in ("O", "R", "W"):
            self._add_right(owner, o, right)
        print(
            f"[OK] Объект '{o}' создан. "
            f"Субъект '{owner}' получил права: O (Владение), R (Чтение), W (Запись)."
        )

    def delete_object(self, o: str, who: str) -> None:
        """Команда: удалить объект o; требуется право O у субъекта who."""
        if o not in self.objects:
            raise ValueError(f"Объект '{o}' не найден.")
        if who not in self.subjects:
            raise ValueError(f"Субъект '{who}' не найден.")
        if not self.has_right(who, o, "O"):
            raise PermissionError(
                f"Отказано: субъект '{who}' не имеет права Владения (O) на '{o}'."
            )
        self.objects.remove(o)
        for subj in self.subjects:
            self.acm.get(subj, {}).pop(o, None)
        print(f"[OK] Объект '{o}' удалён субъектом '{who}' (проверка владения пройдена).")

    def grant(self, right: str, o: str, s1: str, s2: str) -> None:
        """Команда: передать право right на объект o от s1 (владелец) субъекту s2."""
        right = right.upper()
        if right not in RIGHTS:
            raise ValueError(f"Неверное право '{right}'. Допустимы: O, R, W.")
        if o not in self.objects:
            raise ValueError(f"Объект '{o}' не найден.")
        if s1 not in self.subjects:
            raise ValueError(f"Субъект '{s1}' не найден.")
        if s2 not in self.subjects:
            raise ValueError(f"Субъект '{s2}' не найден.")
        if not self.has_right(s1, o, "O"):
            raise PermissionError(
                f"Отказано: субъект '{s1}' не имеет права Владения (O) на '{o}'."
            )
        if self.has_right(s2, o, right):
            print(
                f"[INFO] Субъект '{s2}' уже имеет право "
                f"{RIGHTS_FULL[right]} ({right}) на '{o}'."
            )
            return
        self._add_right(s2, o, right)
        print(
            f"[OK] Право {RIGHTS_FULL[right]} ({right}) на '{o}' "
            f"передано субъекту '{s2}' субъектом '{s1}'."
        )

    def revoke(self, right: str, o: str, s1: str, s2: str) -> None:
        """Команда: забрать право right на объект o от s2; инициатор s1 (владелец)."""
        right = right.upper()
        if right not in RIGHTS:
            raise ValueError(f"Неверное право '{right}'. Допустимы: O, R, W.")
        if o not in self.objects:
            raise ValueError(f"Объект '{o}' не найден.")
        if s1 not in self.subjects:
            raise ValueError(f"Субъект '{s1}' не найден.")
        if s2 not in self.subjects:
            raise ValueError(f"Субъект '{s2}' не найден.")
        if not self.has_right(s1, o, "O"):
            raise PermissionError(
                f"Отказано: субъект '{s1}' не имеет права Владения (O) на '{o}'."
            )
        if not self.has_right(s2, o, right):
            print(
                f"[INFO] Субъект '{s2}' не имеет права "
                f"{RIGHTS_FULL[right]} ({right}) на '{o}' — нечего изымать."
            )
            return
        self._remove_right(s2, o, right)
        print(
            f"[OK] Право {RIGHTS_FULL[right]} ({right}) на '{o}' "
            f"изъято у субъекта '{s2}' субъектом '{s1}'."
        )

    def show_subject(self, s: str) -> None:
        """Вывод всех прав субъекта s на объекты."""
        if s not in self.subjects:
            raise ValueError(f"Субъект '{s}' не найден.")
        print(f"\n  Права субъекта '{s}':")
        found = False
        for o in self.objects:
            rights = self.acm.get(s, {}).get(o, set())
            if rights:
                rights_str = ", ".join(
                    f"{RIGHTS_FULL[r]}({r})" for r in ["O", "R", "W"] if r in rights
                )
                print(f"    объект '{o}': {rights_str}")
                found = True
        if not found:
            print("    (нет прав ни на один объект)")
        print()

    def show_object(self, o: str) -> None:
        """Вывод всех прав субъектов на объект o."""
        if o not in self.objects:
            raise ValueError(f"Объект '{o}' не найден.")
        print(f"\n  Права на объект '{o}':")
        found = False
        for s in self.subjects:
            rights = self.acm.get(s, {}).get(o, set())
            if rights:
                rights_str = ", ".join(
                    f"{RIGHTS_FULL[r]}({r})" for r in ["O", "R", "W"] if r in rights
                )
                print(f"    субъект '{s}': {rights_str}")
                found = True
        if not found:
            print("    (нет субъектов с правами)")
        print()

    def show_matrix(self) -> None:
        """Вывод полной матрицы доступа."""
        if not self.subjects or not self.objects:
            print("  Матрица пуста (нет субъектов или объектов).")
            return
        col_w = max(max(len(o) for o in self.objects), 8) + 2
        row_h = max(max(len(s) for s in self.subjects), 8) + 2
        header = f"  {'Субъект / Объект':<{row_h}}" + "".join(f"{o:^{col_w}}" for o in self.objects)
        print("\n" + header)
        print("  " + "-" * (row_h + col_w * len(self.objects)))
        for s in self.subjects:
            row = f"  {s:<{row_h}}"
            for o in self.objects:
                rights = self.acm.get(s, {}).get(o, set())
                cell = "".join(r for r in ["O", "R", "W"] if r in rights) or "—"
                row += f"{cell:^{col_w}}"
            print(row)
        print()


# ------------------------------------------------------------------ #
#  Разбор команды                                                      #
# ------------------------------------------------------------------ #

def parse_right_alias(r: str) -> str:
    """Позволяет вводить право как 'O'/'own'/'владение', 'R'/'read'/'чтение', 'W'/'write'/'запись'."""
    mapping = {
        "o": "O", "own": "O", "владение": "O",
        "r": "R", "read": "R", "чтение": "R",
        "w": "W", "write": "W", "запись": "W",
    }
    return mapping.get(r.lower(), r.upper())


HELP_TEXT = """
  Команды:
  ─────────────────────────────────────────────────────
  create_subject <s>                  — создать субъект s
  delete_subject <s>                  — удалить субъект s
  create_object  <o> <owner>          — создать объект o (owner получает O,R,W)
  delete_object  <o> <who>            — удалить объект o (who должен иметь O)
  grant  <O|R|W> <o> <s1> <s2>       — s1 (владелец) передаёт право s2
  revoke <O|R|W> <o> <s1> <s2>       — s1 (владелец) изымает право у s2
  show subject <s>                    — вывод прав субъекта s
  show object  <o>                    — вывод прав на объект o
  matrix                              — вывод полной матрицы доступа
  help                                — эта справка
  exit                                — выход
  ─────────────────────────────────────────────────────
  Права: O=Владение  R=Чтение  W=Запись
  Синонимы прав: own/read/write или владение/чтение/запись
"""


def dispatch(model: HRUModel, line: str) -> bool:
    """Разобрать и выполнить команду. Возвращает False при команде exit."""
    parts = line.strip().split()
    if not parts:
        return True
    cmd = parts[0].lower()

    try:
        if cmd == "exit":
            return False

        elif cmd == "help":
            print(HELP_TEXT)

        elif cmd == "matrix":
            model.show_matrix()

        elif cmd == "create_subject":
            if len(parts) < 2:
                print("[ERR] Использование: create_subject <s>")
            else:
                model.create_subject(parts[1])

        elif cmd == "delete_subject":
            if len(parts) < 2:
                print("[ERR] Использование: delete_subject <s>")
            else:
                model.delete_subject(parts[1])

        elif cmd == "create_object":
            if len(parts) < 3:
                print("[ERR] Использование: create_object <o> <owner>")
            else:
                model.create_object(parts[1], parts[2])

        elif cmd == "delete_object":
            if len(parts) < 3:
                print("[ERR] Использование: delete_object <o> <who>")
            else:
                model.delete_object(parts[1], parts[2])

        elif cmd == "grant":
            if len(parts) < 5:
                print("[ERR] Использование: grant <O|R|W> <o> <s1> <s2>")
            else:
                model.grant(parse_right_alias(parts[1]), parts[2], parts[3], parts[4])

        elif cmd == "revoke":
            if len(parts) < 5:
                print("[ERR] Использование: revoke <O|R|W> <o> <s1> <s2>")
            else:
                model.revoke(parse_right_alias(parts[1]), parts[2], parts[3], parts[4])

        elif cmd == "show":
            if len(parts) < 3:
                print("[ERR] Использование: show subject <s>  |  show object <o>")
            elif parts[1].lower() in ("subject", "субъект"):
                model.show_subject(parts[2])
            elif parts[1].lower() in ("object", "объект"):
                model.show_object(parts[2])
            else:
                print("[ERR] Использование: show subject <s>  |  show object <o>")

        else:
            print(f"[ERR] Неизвестная команда '{cmd}'. Введите 'help' для справки.")

    except (ValueError, PermissionError) as e:
        print(f"[ERR] {e}")

    return True


# ------------------------------------------------------------------ #
#  Демонстрационный сценарий                                           #
# ------------------------------------------------------------------ #

def demo(model: HRUModel) -> None:
    scenario = [
        "create_subject alice",
        "create_subject bob",
        "create_subject carol",
        "create_object file1 alice",
        "create_object file2 alice",
        "show subject alice",
        "show object file1",
        "grant R file1 alice bob",
        "grant W file1 alice bob",
        "show subject bob",
        "revoke W file1 alice bob",
        "show object file1",
        "grant O file1 bob alice",   # должно упасть — bob не владелец
        "delete_object file1 bob",   # должно упасть — bob не владелец
        "delete_object file1 alice",
        "matrix",
        "delete_subject carol",
        "matrix",
    ]
    print("\n" + "=" * 60)
    print("  ДЕМОНСТРАЦИОННЫЙ СЦЕНАРИЙ")
    print("=" * 60)
    for cmd in scenario:
        print(f"\n>>> {cmd}")
        if not dispatch(model, cmd):
            break
    print("\n" + "=" * 60 + "\n")


# ------------------------------------------------------------------ #
#  Точка входа                                                         #
# ------------------------------------------------------------------ #

def main() -> None:
    model = HRUModel()
    print("=" * 60)
    print("  Модель Харрисона–Руззо–Ульмана (HRU)  Лаб. работа №6")
    print("=" * 60)
    print("  Введите 'help' для списка команд, 'demo' для примера.")
    print()

    while True:
        try:
            line = input("hru> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nДо свидания.")
            break

        if line.lower() == "demo":
            demo(model)
            continue

        if not dispatch(model, line):
            print("До свидания.")
            break


if __name__ == "__main__":
    main()
